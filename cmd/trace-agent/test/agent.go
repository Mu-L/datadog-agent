// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package test

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/viper"
	yaml "gopkg.in/yaml.v2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"

	"github.com/DataDog/datadog-agent/pkg/api/security"
	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/core"
	grpcutil "github.com/DataDog/datadog-agent/pkg/util/grpc"

	"github.com/DataDog/datadog-agent/pkg/trace/testutil"
)

// ErrNotInstalled is returned when the trace-agent can not be found in $PATH.
var ErrNotInstalled = errors.New("agent: trace-agent not found in $PATH")

// SecretBackendBinary secret binary name
var SecretBackendBinary = "secret-script.test"

type grpcServer struct {
	pb.UnimplementedAgentSecureServer
}

type agentRunner struct {
	mu  sync.RWMutex // guards pid
	pid int          // agent pid, if running

	port                 int         // agent receiver port
	log                  *safeBuffer // agent log output
	ddAddr               string      // Datadog intake address (host:port)
	bindir               string      // the temporary directory where the trace-agent binary is located
	verbose              bool
	agentServer          *grpc.Server
	agentServerListerner net.Listener
	authToken            string
}

func newAgentRunner(ddAddr string, verbose bool, buildSecretBackend bool) (*agentRunner, error) {
	bindir, err := os.MkdirTemp("", "trace-agent-integration-tests")
	if err != nil {
		return nil, err
	}
	binpath := filepath.Join(bindir, "trace-agent")
	if verbose {
		log.Printf("agent: installing in %s...", binpath)
	}
	// TODO(gbbr): find a way to re-use the same binary within a whole run
	// instead of creating new ones on each test creating a new runner.
	o, err := exec.Command("go", "build", "-tags", "otlp", "-o", binpath, "github.com/DataDog/datadog-agent/cmd/trace-agent").CombinedOutput()
	if err != nil {
		if verbose {
			log.Printf("error installing trace-agent: %v", err)
			log.Print(string(o))
		}
		return nil, ErrNotInstalled
	}

	if buildSecretBackend {
		binSecrets := filepath.Join(bindir, SecretBackendBinary)
		o, err := exec.Command("go", "build", "-o", binSecrets, "./testdata/secretscript.go").CombinedOutput()

		if err != nil {
			if verbose {
				log.Printf("error installing secret-script: %v", err)
				log.Print(string(o))
			}
			return nil, ErrNotInstalled
		}

		if err := os.Chmod(binSecrets, 0700); err != nil {
			if verbose {
				log.Printf("error changing permissions secret-script: %v", err)
			}
			return nil, ErrNotInstalled
		}
	}

	tlsKeyPair, err := buildSelfSignedTLSCertificate("127.0.0.1")
	if err != nil {
		return nil, fmt.Errorf("unable to generate TLS certificate: %v", err)
	}

	// Generate an authentication token and set up our gRPC server to both serve over TLS and authenticate each RPC
	// using the authentication token.
	authToken, err := generateAuthenticationToken()
	if err != nil {
		return nil, fmt.Errorf("unable to generate authentication token: %v", err)
	}

	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(tlsKeyPair)),
		grpc.UnaryInterceptor(grpc_auth.UnaryServerInterceptor(grpcutil.StaticAuthInterceptor(authToken))),
	}

	// Start dummy gRPc server mocking the core agent
	serverListener, err := net.Listen("tcp", "127.0.0.1:5051")
	if err != nil {
		return nil, ErrNotInstalled
	}
	s := grpc.NewServer(serverOpts...)
	pb.RegisterAgentSecureServer(s, &grpcServer{})

	go func() {
		err := s.Serve(serverListener)
		if err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	return &agentRunner{
		bindir:               bindir,
		ddAddr:               ddAddr,
		log:                  newSafeBuffer(),
		verbose:              verbose,
		agentServer:          s,
		agentServerListerner: serverListener,
		authToken:            authToken,
	}, nil
}

// cleanup removes the agent binary.
func (s *agentRunner) cleanup() error {
	s.Kill()
	s.agentServer.Stop()
	s.agentServerListerner.Close()
	return os.RemoveAll(s.bindir)
}

// Run runs the agent using a given yaml config. If an agent is already running,
// it will be killed.
func (s *agentRunner) Run(conf []byte) error {
	cfgPath, err := s.createConfigFile(conf)
	if err != nil {
		return fmt.Errorf("agent: error creating config: %v", err)
	}
	timeout := time.After(10 * time.Second)
	exit := s.runAgentConfig(cfgPath)
	for {
		select {
		case err := <-exit:
			return fmt.Errorf("agent: %v, log output:\n%s", err, s.Log())
		case <-timeout:
			return fmt.Errorf("agent: timed out waiting for start, log:\n%s", s.Log())
		default:
			if strings.Contains(s.log.String(), "Listening for traces at") {
				if s.verbose {
					log.Print("agent: Listening for traces")
				}
				return nil
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

// Log returns the tail of the agent log (up to 1M).
func (s *agentRunner) Log() string { return s.log.String() }

// PID returns the process ID of the trace-agent. If the trace-agent is not running
// as a child process of this program, it will be 0.
func (s *agentRunner) PID() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pid
}

// Addr returns the address of the trace agent receiver.
func (s *agentRunner) Addr() string { return fmt.Sprintf("localhost:%d", s.port) }

// Kill stops a running trace-agent, if it was started by this process.
func (s *agentRunner) Kill() {
	pid := s.PID()
	if pid == 0 {
		return
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		if s.verbose {
			log.Print("couldn't find process: ", err)
		}
		return
	}
	if err := proc.Kill(); err != nil {
		if s.verbose {
			log.Print("couldn't kill running agent: ", err)
		}
		return
	}
	if _, err := proc.Wait(); err != nil {
		if s.verbose {
			log.Print("error waiting for process to exit", err)
		}
		return
	}

	s.mu.Lock()
	s.pid = 0
	s.mu.Unlock()
}

func (s *agentRunner) runAgentConfig(path string) <-chan error {
	s.Kill()
	cmd := exec.Command(filepath.Join(s.bindir, "trace-agent"), "--config", path)
	s.log.Reset()
	cmd.Stdout = s.log
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		log.Print("error starting process: ", err)
	}

	s.mu.Lock()
	s.pid = cmd.Process.Pid
	s.mu.Unlock()

	ch := make(chan error, 1) // don't block
	go func() {
		ch <- cmd.Wait()
		if s.verbose {
			log.Printf("agent: killed")
		}
	}()
	return ch
}

// createConfigFile creates a config file from the given config, altering the
// apm_config.apm_dd_url and log_level values and returns the full path.
func (s *agentRunner) createConfigFile(conf []byte) (string, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(conf)); err != nil {
		return "", err
	}
	if v.IsSet("apm_config.receiver_port") {
		s.port = v.GetInt("apm_config.receiver_port")
	} else {
		if p, err := testutil.FindTCPPort(); err != nil {
			fmt.Printf("There was an error finding a free port: %v. Trying 8126.\n", err)
			s.port = 8126
		} else {
			s.port = p
		}
		v.Set("apm_config.receiver_port", s.port)
	}
	v.Set("apm_config.apm_dd_url", "http://"+s.ddAddr)
	if !v.IsSet("api_key") {
		v.Set("api_key", "testing123")
	}
	if !v.IsSet("apm_config.trace_writer.flush_period_seconds") {
		v.Set("apm_config.trace_writer.flush_period_seconds", 0.1)
	}
	if !v.IsSet("log_level") {
		v.Set("log_level", "debug")
	}

	v.Set("cmd_port", s.agentServerListerner.Addr().(*net.TCPAddr).Port)

	out, err := yaml.Marshal(v.AllSettings())
	if err != nil {
		return "", err
	}
	confFile, err := os.Create(filepath.Join(s.bindir, "datadog.yaml"))
	if err != nil {
		return "", err
	}
	if _, err := confFile.Write(out); err != nil {
		return "", err
	}
	if err := confFile.Close(); err != nil {
		return "", err
	}
	// create auth_token file
	authTokenFile, err := os.Create(filepath.Join(s.bindir, "auth_token"))
	if err != nil {
		return "", err
	}
	if _, err := authTokenFile.Write([]byte(s.authToken)); err != nil {
		return "", err
	}
	if err := authTokenFile.Close(); err != nil {
		return "", err
	}
	return confFile.Name(), nil
}

func buildSelfSignedTLSCertificate(host string) (*tls.Certificate, error) {
	hosts := []string{host}
	_, certPEM, key, err := security.GenerateRootCert(hosts, 2048)
	if err != nil {
		return nil, errors.New("unable to generate certificate")
	}

	// PEM encode the private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to generate TLS key pair: %v", err)
	}

	return &pair, nil
}

func generateAuthenticationToken() (string, error) {
	rawToken := make([]byte, 32)
	_, err := rand.Read(rawToken)
	if err != nil {
		return "", fmt.Errorf("can't create authentication token value: %s", err)
	}

	return hex.EncodeToString(rawToken), nil
}
