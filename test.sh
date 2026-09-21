#! /bin/bash
#
# Zappa unit test runner.
#
# NOTE: Every test below must be run MANUALLY.
#
#   1. Activate a virtualenv running Python 3.6/3.7/3.8
#   2. Install the dependencies:
#        pip install -r requirements.txt -r test_requirements.txt
#   3. Run this script from the repository root:
#        ./test.sh
#
# Exit on the first failing command so a broken unit is never missed.
set -e

#
# Full unit suite (mocked AWS calls; no AWS account or network needed).
#
echo "==> Running the full Zappa unit suite (manual run).."
nosetests --with-coverage --cover-package=zappa

#
# Deployment-safety units only (task: deployment hardening).
# Covers:
#   - deploy_api_gateway pre-flight checks (Lambda exists, IAM role
#     exists/assumable/minimum permissions, REST API exists)
#   - automatic cleanup of half-created API Gateway resources on failure
#   - rollback_lambda_function_version restoring code AND configuration
#   - the S3-backed cross-machine deployment lock (core + CLI wrappers)
#
echo "==> Running the deployment-safety units (manual run).."
nosetests tests/test_deployment_safety.py -v

#
# If nose is unavailable, the same units can be run with plain unittest:
#   python -m unittest tests.test_deployment_safety -v
#
# For a specific test:
#   nosetests tests.test_deployment_safety:TestDeploymentLock -v
