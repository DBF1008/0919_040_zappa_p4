#! /bin/bash
#
# Zappa test runner.
#
# The deployment-safety unit tests (pre-flight validation, full code+config
# rollback, distributed deployment lock) are fully mocked with botocore
# Stubbers and require no AWS account or network access.
#
# Usage (run manually):
#   ./test.sh                      # run the deployment-safety unit tests
#   ./test.sh all                  # run the entire test suite
#   ./test.sh tests/tests.py       # run a specific test module
set -e

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

if [ "$1" = "all" ]; then
    echo "Running the full Zappa test suite.."
    exec "$PYTHON" -m pytest -v
fi

if [ -n "$1" ]; then
    exec "$PYTHON" -m pytest -v "$@"
fi

echo "Running deployment-safety unit tests.."
"$PYTHON" -m pytest -v tests/tests_deployment_safety.py
