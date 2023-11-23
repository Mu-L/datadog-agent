// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package fargate_test contains e2e tests for fargate
package fargate_test

import (
	"context"
	"testing"
	"time"

	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/ssm"
	"github.com/pulumi/pulumi-awsx/sdk/go/awsx/awsx"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsecs "github.com/aws/aws-sdk-go-v2/service/ecs"
	awsecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/pulumi/pulumi-awsx/sdk/go/awsx/ecs"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	configCommon "github.com/DataDog/test-infra-definitions/common/config"
	agentComponent "github.com/DataDog/test-infra-definitions/components/datadog/agent"
	awsResources "github.com/DataDog/test-infra-definitions/resources/aws"
	ecsResources "github.com/DataDog/test-infra-definitions/resources/aws/ecs"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/infra"
)

const (
	// Keys
	ecsClusterNameKey = "ecs-cluster-name"
	ecsClusterArnKey  = "ecs-cluster-arn"
	fgTaskDefArnKey   = "fargate-task-arn"
)

type ECSFargateSuite struct {
	suite.Suite
	ctx       context.Context
	stackName string

	ecsClusterArn  string
	ecsClusterName string
	fgTaskDefArn   string
}

func TestECSFargate(t *testing.T) {
	suite.Run(t, &ECSFargateSuite{
		ctx:       context.Background(),
		stackName: "cws-tests-ecs-fg-dev",
	})
}

func (s *ECSFargateSuite) SetupSuite() {
	_, result, err := infra.GetStackManager().GetStack(s.ctx, s.stackName, nil, func(ctx *pulumi.Context) error {
		awsEnv, err := awsResources.NewEnvironment(ctx)
		if err != nil {
			return err
		}

		// Create cluster
		ecsCluster, err := ecsResources.CreateEcsCluster(awsEnv, "cws-cluster")
		if err != nil {
			return err
		}

		// Export cluster’s properties
		ctx.Export(ecsClusterNameKey, ecsCluster.Name)
		ctx.Export(ecsClusterArnKey, ecsCluster.Arn)

		// Associate Fargate capacity provider to the cluster
		_, err = ecsResources.NewClusterCapacityProvider(awsEnv, "cws-cluster-capacity-provider", ecsCluster.Name, pulumi.StringArray{pulumi.String("FARGATE")})
		if err != nil {
			return err
		}

		// Setup agent API key
		apiKeyParam, err := ssm.NewParameter(ctx, awsEnv.Namer.ResourceName("agent-apikey"), &ssm.ParameterArgs{
			Name:  awsEnv.CommonNamer.DisplayName(1011, pulumi.String("agent-apikey")),
			Type:  ssm.ParameterTypeSecureString,
			Value: awsEnv.AgentAPIKey(),
		}, awsEnv.WithProviders(configCommon.ProviderAWS, configCommon.ProviderAWSX))
		if err != nil {
			return err
		}

		// Create task definition
		taskDef, err := ecs.NewFargateTaskDefinition(ctx, "cws-task", &ecs.FargateTaskDefinitionArgs{
			Containers: map[string]ecs.TaskDefinitionContainerDefinitionArgs{
				"datadog-agent": {
					Cpu:       pulumi.IntPtr(0),
					Name:      pulumi.String("datadog-agent"),
					Image:     pulumi.Sprintf(agentComponent.DockerAgentFullImagePath(awsEnv.CommonEnvironment, "public.ecr.aws/datadog/agent")),
					Essential: pulumi.BoolPtr(true),
					Environment: ecs.TaskDefinitionKeyValuePairArray{
						ecs.TaskDefinitionKeyValuePairArgs{
							Name:  pulumi.StringPtr("DD_HOSTNAME"),
							Value: pulumi.StringPtr("cws-tests-fg-task"),
						},
						ecs.TaskDefinitionKeyValuePairArgs{
							Name:  pulumi.StringPtr("ECS_FARGATE"),
							Value: pulumi.StringPtr("true"),
						},
					},
					Secrets: ecs.TaskDefinitionSecretArray{
						ecs.TaskDefinitionSecretArgs{
							Name:      pulumi.String("DD_API_KEY"),
							ValueFrom: apiKeyParam.Name,
						},
					},
					HealthCheck: &ecs.TaskDefinitionHealthCheckArgs{
						Retries:     pulumi.IntPtr(2),
						Command:     pulumi.ToStringArray([]string{"CMD-SHELL", "/probe.sh"}),
						StartPeriod: pulumi.IntPtr(60),
						Interval:    pulumi.IntPtr(30),
						Timeout:     pulumi.IntPtr(5),
					},
					LogConfiguration: ecs.TaskDefinitionLogConfigurationArgs{
						LogDriver: pulumi.String("awsfirelens"),
						Options: pulumi.StringMap{
							"Name":           pulumi.String("datadog"),
							"Host":           pulumi.String("http-intake.logs.datadoghq.com"),
							"TLS":            pulumi.String("on"),
							"dd_service":     pulumi.String("datadog-agent"),
							"dd_source":      pulumi.String("datadog-agent"),
							"dd_message_key": pulumi.String("log"),
							"provider":       pulumi.String("ecs"),
						},
						SecretOptions: ecs.TaskDefinitionSecretArray{
							ecs.TaskDefinitionSecretArgs{
								Name:      pulumi.String("apikey"),
								ValueFrom: apiKeyParam.Name,
							},
						},
					},
					PortMappings: ecs.TaskDefinitionPortMappingArray{},
					VolumesFrom:  ecs.TaskDefinitionVolumeFromArray{},
				},
				"log_router": {
					Cpu:       pulumi.IntPtr(0),
					User:      pulumi.StringPtr("0"),
					Name:      pulumi.String("log_router"),
					Image:     pulumi.String("amazon/aws-for-fluent-bit:latest"),
					Essential: pulumi.BoolPtr(true),
					FirelensConfiguration: ecs.TaskDefinitionFirelensConfigurationArgs{
						Type: pulumi.String("fluentbit"),
						Options: pulumi.StringMap{
							"enable-ecs-log-metadata": pulumi.String("true"),
						},
					},
					MountPoints:  ecs.TaskDefinitionMountPointArray{},
					Environment:  ecs.TaskDefinitionKeyValuePairArray{},
					PortMappings: ecs.TaskDefinitionPortMappingArray{},
					VolumesFrom:  ecs.TaskDefinitionVolumeFromArray{},
				},
			},
			Cpu:    pulumi.StringPtr("2048"),
			Memory: pulumi.StringPtr("4096"),
			ExecutionRole: &awsx.DefaultRoleWithPolicyArgs{
				RoleArn: pulumi.StringPtr(awsEnv.ECSTaskExecutionRole()),
			},
			TaskRole: &awsx.DefaultRoleWithPolicyArgs{
				RoleArn: pulumi.StringPtr(awsEnv.ECSTaskRole()),
			},
			Family: awsEnv.CommonNamer.DisplayName(255, pulumi.String("cws-task")),
		}, awsEnv.WithProviders(configCommon.ProviderAWS, configCommon.ProviderAWSX))
		if err != nil {
			return err
		}

		_, err = ecsResources.FargateService(awsEnv, "cws-service", ecsCluster.Arn, taskDef.TaskDefinition.Arn())
		if err != nil {
			return err
		}

		// Export task definition's properties
		ctx.Export(fgTaskDefArnKey, taskDef.TaskDefinition.Arn())

		return nil
	}, false)
	s.Require().NoError(err)

	s.ecsClusterArn = result.Outputs[ecsClusterArnKey].Value.(string)
	s.ecsClusterName = result.Outputs[ecsClusterNameKey].Value.(string)
	s.fgTaskDefArn = result.Outputs[fgTaskDefArnKey].Value.(string)
}

func (s *ECSFargateSuite) TearDownSuite() {
	err := infra.GetStackManager().DeleteStack(s.ctx, s.stackName)
	s.Assert().NoError(err)
}

func (s *ECSFargateSuite) Test00UpAndRunning() {
	cfg, err := awsconfig.LoadDefaultConfig(s.ctx)
	s.Require().NoErrorf(err, "Failed to load AWS config")

	client := awsecs.NewFromConfig(cfg)

	s.Run("cluster-ready", func() {
		ready := s.EventuallyWithTf(func(collect *assert.CollectT) {
			var listServicesToken string
			listServicesMaxResults := int32(100)
			for nextToken := &listServicesToken; nextToken != nil; {
				clustersList, err := client.ListClusters(s.ctx, &awsecs.ListClustersInput{
					MaxResults: &listServicesMaxResults,
					NextToken:  nextToken,
				})
				if !assert.NoErrorf(collect, err, "Failed to list ECS clusters") {
					return
				}
				nextToken = clustersList.NextToken
				for _, clusterArn := range clustersList.ClusterArns {
					if clusterArn != s.ecsClusterArn {
						continue
					}
					clusters, err := client.DescribeClusters(s.ctx, &awsecs.DescribeClustersInput{
						Clusters: []string{clusterArn},
					})
					if !assert.NoErrorf(collect, err, "Failed to describe ECS cluster %s", clusterArn) {
						return
					}
					if !assert.Len(collect, clusters.Clusters, 1) {
						return
					}
					if !assert.NotNil(collect, clusters.Clusters[0].Status) {
						return
					}
					_ = assert.Equal(collect, "ACTIVE", *(clusters.Clusters[0].Status))
					return
				}
			}
			assert.Fail(collect, "Failed to find cluster")
		}, 5*time.Minute, 20*time.Second, "Failed to wait for ecs cluster to become ready (name:%s arn:%s)", s.ecsClusterName, s.ecsClusterArn)
		s.Require().True(ready, "Cluster isn't ready, stopping tests here")
	})

	s.Run("tasks-ready", func() {
		ready := s.EventuallyWithTf(func(collect *assert.CollectT) {
			taskReady := false
			var listServicesToken string
			listServicesMaxResults := int32(10)
			for nextServicesToken := &listServicesToken; nextServicesToken != nil; {
				servicesList, err := client.ListServices(s.ctx, &awsecs.ListServicesInput{
					Cluster:    &s.ecsClusterArn,
					MaxResults: &listServicesMaxResults,
					NextToken:  nextServicesToken,
				})
				if !assert.NoErrorf(collect, err, "Failed to list ECS services of cluster %s", s.ecsClusterArn) {
					return
				}
				nextServicesToken = servicesList.NextToken
				serviceDescriptions, err := client.DescribeServices(s.ctx, &awsecs.DescribeServicesInput{
					Cluster:  &s.ecsClusterName,
					Services: servicesList.ServiceArns,
				})
				if !assert.NoErrorf(collect, err, "Failed to describe ECS services %v", servicesList.ServiceArns) {
					return
				}
				for _, service := range serviceDescriptions.Services {
					var listTasksToken string
					listTasksMaxResults := int32(100)
					for nextTasksToken := &listTasksToken; nextTasksToken != nil; {
						tasksList, err := client.ListTasks(s.ctx, &awsecs.ListTasksInput{
							Cluster:       &s.ecsClusterArn,
							ServiceName:   service.ServiceName,
							DesiredStatus: awsecstypes.DesiredStatusRunning,
							MaxResults:    &listTasksMaxResults,
							NextToken:     nextTasksToken,
						})
						if !assert.NoErrorf(collect, err, "Failed to list ECS tasks of cluster %s and service %s", s.ecsClusterArn, *service.ServiceName) {
							return
						}
						nextTasksToken = tasksList.NextToken

						tasks, err := client.DescribeTasks(s.ctx, &awsecs.DescribeTasksInput{
							Cluster: &s.ecsClusterArn,
							Tasks:   tasksList.TaskArns,
						})
						if !assert.NoErrorf(collect, err, "Failed to describe ECS tasks %v", tasksList.TaskArns) {
							return
						}
						for _, task := range tasks.Tasks {
							running := assert.Equal(collect, string(awsecstypes.DesiredStatusRunning), *task.LastStatus)
							notUnhealthy := assert.NotEqual(collect, awsecstypes.HealthStatusUnhealthy, task.HealthStatus,
								"Task %s of service %s is unhealthy", *task.TaskArn, *service.ServiceName)
							if task.TaskDefinitionArn != nil && *task.TaskDefinitionArn == s.fgTaskDefArn {
								taskReady = running && notUnhealthy
							}
						}
					}
				}
			}
			assert.True(collect, taskReady, "Failed to validate the state of task %s", s.fgTaskDefArn)
		}, 5*time.Minute, 10*time.Second, "Failed to wait for fargate tasks to become ready")
		s.Require().True(ready, "Tasks aren't ready, stopping tests here")
	})
}
