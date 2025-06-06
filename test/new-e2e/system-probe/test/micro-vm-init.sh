#!/bin/bash
set -eEuo pipefail

docker_dir=/kmt-dockers

# Add provisioning steps here !
## Start docker if available, some images (e.g. SUSE arm64 for CWS) do not have it installed
if command -v docker ; then
    systemctl start docker

    ## Load docker images
    if [[ -d "${docker_dir}" ]]; then
        find "${docker_dir}" -maxdepth 1 -type f -exec docker load -i {} \;
    fi
else
    echo "Docker not available, skipping docker provisioning"
fi
# VM provisioning end !

# Start tests
code=0

/opt/testing-tools/test-runner "$@" || code=$?

if [[ -f "/job_env.txt" ]]; then
    cp /job_env.txt /ci-visibility/junit/
else
    echo "job_env.txt not found. Continuing without it."
fi

tar -C /ci-visibility/testjson -czvf /ci-visibility/testjson.tar.gz .
tar -C /ci-visibility/junit -czvf /ci-visibility/junit.tar.gz .

if [ "${COLLECT_COMPLEXITY:-}" = "yes" ]; then
    echo "Collecting complexity data..."
    mkdir -p /verifier-complexity
    arch=$(uname -m)
    if [[ "${arch}" == "aarch64" ]]; then
        arch="arm64"
    fi

    test_root=$(echo "$@" | sed 's/.*-test-root \([^ ]*\).*/\1/')
    export DD_SYSTEM_PROBE_BPF_DIR="${test_root}/pkg/ebpf/bytecode/build/${arch}"

    # Set the value of COMPLEXITY_CALC_MAX_MEM_MB to 6000 if not set by the environment
    if [[ -z "${COMPLEXITY_CALC_MAX_MEM_MB:-}" ]]; then
        export COMPLEXITY_CALC_MAX_MEM_MB=6000
    fi

    # Limit maximum memory usage of the calculator to avoid OOM errors affecting the entire connector
    ulimit -v $((COMPLEXITY_CALC_MAX_MEM_MB * 1024))

    # The debug.SetMemoryLimit function we use in the calculator for memory
    # limits only takes into account memory managed by the Go runtime, so we
    # tell it to try to keep a smaller memory limit than the one enforced by
    # ulimit, to reduce the chances of going above that hard limit.
    COMPLEXITY_GO_MAX_MEM_LIMIT=$((COMPLEXITY_CALC_MAX_MEM_MB * 95 / 100))

    if /opt/testing-tools/verifier-calculator -line-complexity -complexity-data-dir /verifier-complexity/complexity-data  -summary-output /verifier-complexity/verifier_stats.json -memory-limit-mb "${COMPLEXITY_GO_MAX_MEM_LIMIT}" &> /verifier-complexity/calculator.log ; then
        echo "Data collected, creating tarball at /verifier-complexity.tar.gz"
        tar -C /verifier-complexity -czf /verifier-complexity.tar.gz . || echo "Failed to created verifier-complexity.tar.gz"
    else
        echo "Failed to collect complexity data"
        echo "Calculator log:"
        cat /verifier-complexity/calculator.log
    fi
fi

exit ${code}
