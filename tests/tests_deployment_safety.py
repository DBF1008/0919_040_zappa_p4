# -*- coding: utf8 -*-
"""
Unit tests for the deployment-safety features:

1. core.py pre-flight validation (Lambda existence + IAM role/permissions)
2. core.py full rollback (code AND configuration) + half-finished cleanup
3. cli.py distributed deployment lock (concurrent `zappa deploy` protection)

These tests use botocore Stubber clients, so no AWS account or network access
is required. Run them manually with ./test.sh or:

    python -m pytest tests/tests_deployment_safety.py -v
"""
import os
import unittest

import botocore
import botocore.session
import mock
from botocore.stub import Stubber
from click.exceptions import ClickException

from zappa import core as zappa_core_module
from zappa.cli import ZappaCLI
from zappa.core import (
    Zappa,
    LambdaFunctionNotFound,
    IAMRoleValidationError,
    DeploymentLockError,
    DEPLOYMENT_LOCK_TABLE_NAME,
)


def make_zappa():
    """Build a Zappa object with real, stubbed boto clients (no credentials)."""
    zappa = Zappa(
        boto_session=mock.Mock(),
        profile_name="test",
        aws_region="us-east-1",
        load_credentials=False,
    )
    session = botocore.session.get_session()
    for service in ('lambda', 'iam', 's3', 'cloudformation',
                    'dynamodb', 'sts', 'apigateway'):
        pass
        setattr(zappa, '{}_client'.format(service),
                session.create_client(service, region_name='us-east-1'))
    zappa.cf_client = session.create_client(
        'cloudformation', region_name='us-east-1')
    return zappa


class TestLambdaExistencePreflight(unittest.TestCase):
    def setUp(self):
        self.zappa = make_zappa()
        self.stubber = Stubber(self.zappa.lambda_client)
        self.zappa.lambda_client = self.stubber.client
        self.stubber.activate()
        self.addCleanup(self.stubber.deactivate)

    def test_lambda_function_exists_true(self):
        self.stubber.add_response(
            'get_function_configuration',
            {'FunctionName': 'myapp-dev', 'Version': '$LATEST'})
        self.assertTrue(self.zappa.lambda_function_exists('myapp-dev'))

    def test_lambda_function_exists_false_when_missing(self):
        self.stubber.add_client_error(
            'get_function_configuration',
            service_error_code='ResourceNotFoundException')
        self.assertFalse(self.zappa.lambda_function_exists('myapp-dev'))

    def test_assert_raises_when_missing(self):
        self.stubber.add_client_error(
            'get_function_configuration',
            service_error_code='ResourceNotFoundException')
        with self.assertRaises(LambdaFunctionNotFound):
            self.zappa.assert_lambda_function_exists('myapp-dev')

    def test_assert_passes_when_present(self):
        self.stubber.add_response(
            'get_function_configuration',
            {'FunctionName': 'myapp-dev', 'Version': '$LATEST'})
        self.assertTrue(
            self.zappa.assert_lambda_function_exists('myapp-dev'))

    def test_other_client_error_is_reraised(self):
        self.stubber.add_client_error(
            'get_function_configuration',
            service_error_code='AccessDeniedException')
        with self.assertRaises(botocore.exceptions.ClientError):
            self.zappa.lambda_function_exists('myapp-dev')


LAMBDA_TRUST_POLICY = {
    'Version': '2012-10-17',
    'Statement': [{
        'Effect': 'Allow',
        'Principal': {'Service': 'lambda.amazonaws.com'},
        'Action': 'sts:AssumeRole',
    }],
}
ROLE_ARN = 'arn:aws:iam::123456789012:role/ZappaLambdaExecution'


class TestIAMRoleValidation(unittest.TestCase):
    def setUp(self):
        self.zappa = make_zappa()
        self.zappa.credentials_arn = ROLE_ARN
        self.iam_stubber = Stubber(self.zappa.iam_client)
        self.zappa.iam_client = self.iam_stubber.client
        self.iam_stubber.activate()
        self.addCleanup(self.iam_stubber.deactivate)
        # The Zappa object also has an iam resource; stub get_credentials_arn.
        self.zappa.get_credentials_arn = mock.Mock(
            return_value=(mock.Mock(), ROLE_ARN))

    def _role_response(self, trust=LAMBDA_TRUST_POLICY):
        return {'Role': {
            'Path': '/',
            'RoleName': 'ZappaLambdaExecution',
            'Arn': ROLE_ARN,
            'AssumeRolePolicyDocument': trust,
        }}

    def test_valid_role_passes(self):
        self.iam_stubber.add_response('get_role', self._role_response())
        self.iam_stubber.add_response(
            'simulate_principal_policy',
            {'EvaluationResults': [
                {'EvalActionName': action, 'EvalDecision': 'allowed'}
                for action in ('logs:CreateLogGroup',
                               'logs:CreateLogStream',
                               'logs:PutLogEvents',
                               'lambda:InvokeFunction')]})
        warnings = self.zappa.validate_iam_role()
        self.assertEqual(warnings, [])

    def test_missing_role_raises(self):
        self.iam_stubber.add_client_error(
            'get_role', service_error_code='NoSuchEntity')
        with self.assertRaises(IAMRoleValidationError):
            self.zappa.validate_iam_role()

    def test_role_without_lambda_trust_raises(self):
        bad_trust = {
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': 'ec2.amazonaws.com'},
                'Action': 'sts:AssumeRole',
            }],
        }
        self.iam_stubber.add_response(
            'get_role', self._role_response(trust=bad_trust))
        with self.assertRaises(IAMRoleValidationError) as ctx:
            self.zappa.validate_iam_role()
        self.assertIn('lambda.amazonaws.com', str(ctx.exception))

    def test_denied_required_action_raises(self):
        self.iam_stubber.add_response('get_role', self._role_response())
        results = [
            {'EvalActionName': 'logs:PutLogEvents',
             'EvalDecision': 'implicitDeny'},
        ]
        self.iam_stubber.add_response(
            'simulate_principal_policy',
            {'EvaluationResults': results})
        with self.assertRaises(IAMRoleValidationError) as ctx:
            self.zappa.validate_iam_role(
                required_actions=['logs:PutLogEvents'])
        self.assertIn('logs:PutLogEvents', str(ctx.exception))

    def test_simulator_access_denied_returns_warning(self):
        self.iam_stubber.add_response('get_role', self._role_response())
        self.iam_stubber.add_client_error(
            'simulate_principal_policy',
            service_error_code='AccessDenied')
        warnings = self.zappa.validate_iam_role()
        self.assertEqual(len(warnings), 1)
        self.assertIn('simulator', warnings[0])


class TestDeployerPermissionValidation(unittest.TestCase):
    def setUp(self):
        self.zappa = make_zappa()
        self.iam_stubber = Stubber(self.zappa.iam_client)
        self.sts_stubber = Stubber(self.zappa.sts_client)
        self.zappa.iam_client = self.iam_stubber.client
        self.zappa.sts_client = self.sts_stubber.client
        self.iam_stubber.activate()
        self.sts_stubber.activate()
        self.addCleanup(self.iam_stubber.deactivate)
        self.addCleanup(self.sts_stubber.deactivate)

    def test_deployer_with_permissions_passes(self):
        self.sts_stubber.add_response(
            'get_caller_identity',
            {'UserId': 'AIDAIOSFODNN7EXAMPLE',
             'Account': '123456789012',
             'Arn': 'arn:aws:iam::123456789012:user/deployer'})
        self.iam_stubber.add_response(
            'simulate_principal_policy',
            {'EvaluationResults': [
                {'EvalActionName': 'lambda:CreateFunction',
                 'EvalDecision': 'allowed'}]})
        warnings = self.zappa.validate_deployer_permissions(
            required_actions=['lambda:CreateFunction'])
        self.assertEqual(warnings, [])

    def test_deployer_missing_permission_raises(self):
        self.sts_stubber.add_response(
            'get_caller_identity',
            {'UserId': 'AIDAIOSFODNN7EXAMPLE',
             'Account': '123456789012',
             'Arn': 'arn:aws:iam::123456789012:user/deployer'})
        self.iam_stubber.add_response(
            'simulate_principal_policy',
            {'EvaluationResults': [
                {'EvalActionName': 'iam:PassRole',
                 'EvalDecision': 'implicitDeny'}]})
        with self.assertRaises(IAMRoleValidationError):
            self.zappa.validate_deployer_permissions(
                required_actions=['iam:PassRole'])

    def test_assumed_role_identity_skips_with_warning(self):
        self.sts_stubber.add_response(
            'get_caller_identity',
            {'UserId': 'AROA1234:session',
             'Account': '123456789012',
             'Arn': 'arn:aws:sts::123456789012:assumed-role/Deploy/x'})
        warnings = self.zappa.validate_deployer_permissions()
        self.assertEqual(len(warnings), 1)


class TestFullRollback(unittest.TestCase):
    def setUp(self):
        self.zappa = make_zappa()
        self.lambda_stubber = Stubber(self.zappa.lambda_client)
        self.zappa.lambda_client = self.lambda_stubber.client
        self.lambda_stubber.activate()
        self.addCleanup(self.lambda_stubber.deactivate)
        self.zappa.credentials_arn = ROLE_ARN
        # Avoid HTTP fetch of the code payload.
        self._code_payload = b'PK\x03\x04-fake-zip-bytes'

    def _stub_list_versions(self, versions):
        self.lambda_stubber.add_response(
            'list_versions_by_function',
            {'Versions': [
                {'Version': str(v), 'FunctionArn':
                 'arn:aws:lambda:us-east-1:123:function:f:{}'.format(v)}
                for v in versions]})

    def test_not_enough_revisions_returns_false(self):
        self._stub_list_versions(['$LATEST'])
        result = self.zappa.rollback_lambda_function_version(
            'f', versions_back=1, restore_configuration=True)
        self.assertFalse(result)

    def test_configuration_snapshot_shape(self):
        self.lambda_stubber.add_response(
            'get_function_configuration',
            {'FunctionName': 'f',
             'Runtime': 'python3.7',
             'Role': ROLE_ARN,
             'Handler': 'handler.lambda_handler',
             'Description': 'd',
             'Timeout': 60,
             'MemorySize': 256,
             'VpcConfig': {'SubnetIds': ['subnet-1'],
                           'SecurityGroupIds': ['sg-1'],
                           'VpcId': 'vpc-1'},
             'Environment': {'Variables': {'A': 'B'}},
             'KMSKeyArn': 'arn:kms:key',
             'TracingConfig': {'Mode': 'Active'},
             'Layers': [{'Arn': 'arn:layer:1', 'CodeSize': 1}],
             'DeadLetterConfig': {'TargetArn': 'arn:sqs:q'}})
        self.lambda_stubber.add_response(
            'get_function_concurrency',
            {'ReservedConcurrentExecutions': 7})
        snapshot = self.zappa.get_lambda_configuration_snapshot('f')
        self.assertEqual(snapshot['Runtime'], 'python3.7')
        self.assertEqual(snapshot['Layers'], ['arn:layer:1'])
        self.assertEqual(snapshot['VpcConfig']['SubnetIds'], ['subnet-1'])
        self.assertNotIn('VpcId', snapshot['VpcConfig'])
        self.assertEqual(snapshot['ReservedConcurrentExecutions'], 7)
        self.assertEqual(snapshot['DeadLetterConfig']['TargetArn'],
                         'arn:sqs:q')

    def test_restore_configuration_invokes_update(self):
        snapshot = {
            'Runtime': 'python3.7',
            'Role': ROLE_ARN,
            'Handler': 'handler.lambda_handler',
            'Description': 'd',
            'Timeout': 60,
            'MemorySize': 256,
            'VpcConfig': {'SubnetIds': [], 'SecurityGroupIds': []},
            'Environment': {'Variables': {}},
            'KMSKeyArn': '',
            'TracingConfig': {'Mode': 'PassThrough'},
            'Layers': [],
            'ReservedConcurrentExecutions': None,
        }
        self.lambda_stubber.add_response(
            'update_function_configuration',
            {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:f'})
        self.lambda_stubber.add_response(
            'delete_function_concurrency', {})
        arn = self.zappa.restore_lambda_configuration('f', snapshot)
        self.assertIn('function:f', arn)

    @mock.patch('zappa.core.requests.get')
    def test_full_rollback_restores_code_and_config_and_publishes(
            self, mock_get):
        # Two published versions (1, 2) + $LATEST.
        self._stub_list_versions(['$LATEST', '1', '2'])
        # Snapshot taken against target version 1.
        self.lambda_stubber.add_response(
            'get_function_configuration',
            {'FunctionName': 'f',
             'Runtime': 'python3.6',
             'Role': ROLE_ARN,
             'Handler': 'old.handler',
             'Timeout': 30,
             'MemorySize': 512,
             'VpcConfig': {'SubnetIds': [], 'SecurityGroupIds': []},
             'Environment': {'Variables': {'OLD': '1'}},
             'KMSKeyArn': '',
             'TracingConfig': {'Mode': 'PassThrough'},
             'Layers': []})
        self.lambda_stubber.add_response(
            'get_function_concurrency', {})
        # get_function -> signed code URL
        self.lambda_stubber.add_response(
            'get_function',
            {'Code': {'Location': 'https://s3.example/signed-url'}})
        # Code fetch
        mock_get.return_value = mock.Mock(
            status_code=200, content=self._code_payload)
        # update_function_code (Publish=False)
        self.lambda_stubber.add_response(
            'update_function_code',
            {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:f',
             'Version': '$LATEST'})
        # restore configuration
        self.lambda_stubber.add_response(
            'update_function_configuration',
            {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:f'})
        self.lambda_stubber.add_response(
            'delete_function_concurrency', {})
        # publish new version
        self.lambda_stubber.add_response(
            'publish_version',
            {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:f:3',
             'Version': '3'})
        # no ALB alias -> ResourceNotFound
        self.lambda_stubber.add_client_error(
            'get_alias', service_error_code='ResourceNotFoundException')

        arn = self.zappa.rollback_lambda_function_version(
            'f', versions_back=1, publish=True,
            restore_configuration=True)
        self.assertEqual(
            arn, 'arn:aws:lambda:us-east-1:123:function:f:3')

    @mock.patch('zappa.core.requests.get')
    def test_code_only_rollback_does_not_restore_config(self, mock_get):
        self._stub_list_versions(['$LATEST', '1', '2'])
        self.lambda_stubber.add_response(
            'get_function',
            {'Code': {'Location': 'https://s3.example/signed-url'}})
        mock_get.return_value = mock.Mock(
            status_code=200, content=self._code_payload)
        # update_function_code with Publish=True (default path when
        # restore_configuration=False): our implementation passes
        # Publish=False then publish_version explicitly.
        self.lambda_stubber.add_response(
            'update_function_code',
            {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:f',
             'Version': '$LATEST'})
        self.lambda_stubber.add_response(
            'publish_version',
            {'FunctionArn': 'arn:aws:lambda:us-east-1:123:function:f:3',
             'Version': '3'})
        self.lambda_stubber.add_client_error(
            'get_alias', service_error_code='ResourceNotFoundException')

        arn = self.zappa.rollback_lambda_function_version(
            'f', versions_back=1, restore_configuration=False)
        self.assertTrue(arn.endswith(':3'))


class TestCleanupFailedDeployment(unittest.TestCase):
    def setUp(self):
        self.zappa = make_zappa()
        self.lambda_stubber = Stubber(self.zappa.lambda_client)
        self.s3_stubber = Stubber(self.zappa.s3_client)
        self.cf_stubber = Stubber(self.zappa.cf_client)
        self.zappa.lambda_client = self.lambda_stubber.client
        self.zappa.s3_client = self.s3_stubber.client
        self.zappa.cf_client = self.cf_stubber.client
        self.lambda_stubber.activate()
        self.s3_stubber.activate()
        self.cf_stubber.activate()
        self.addCleanup(self.lambda_stubber.deactivate)
        self.addCleanup(self.s3_stubber.deactivate)
        self.addCleanup(self.cf_stubber.deactivate)

    def test_cleanup_removes_everything_created(self):
        # delete_stack: describe finds a Zappa-tagged stack, then delete.
        self.cf_stubber.add_response(
            'describe_stacks',
            {'Stacks': [{'StackName': 'f',
                         'Tags': [{'Key': 'ZappaProject', 'Value': 'f'}]}]})
        self.cf_stubber.add_response('delete_stack', {})
        # The stack_delete_complete waiter polls describe_stacks until AWS
        # reports the stack is gone (ValidationError -> success).
        self.cf_stubber.add_client_error(
            'describe_stacks', service_error_code='ValidationError')
        # Lambda removal
        self.lambda_stubber.add_response('delete_function', {})
        # S3 object removal
        self.s3_stubber.add_response('delete_object', {})

        self.zappa.cleanup_failed_deployment(
            'f', created_lambda=True, s3_keys=['pkg.zip'],
            bucket_name='bucket')

    def test_cleanup_keeps_preexisting_lambda(self):
        # Stack absent: delete_stack returns False via describe error.
        self.cf_stubber.add_client_error(
            'describe_stacks', service_error_code='ValidationError')
        # created_lambda=False -> no delete_function call expected.
        self.zappa.cleanup_failed_deployment(
            'f', created_lambda=False)


class TestDeploymentLock(unittest.TestCase):
    def setUp(self):
        self.zappa = make_zappa()
        self.ddb_stubber = Stubber(self.zappa.dynamodb_client)
        self.zappa.dynamodb_client = self.ddb_stubber.client
        self.ddb_stubber.activate()
        self.addCleanup(self.ddb_stubber.deactivate)

    def _stub_table_exists(self):
        self.ddb_stubber.add_response(
            'describe_table',
            {'Table': {'TableName': DEPLOYMENT_LOCK_TABLE_NAME,
                       'TableStatus': 'ACTIVE'}})

    def test_acquire_when_free(self):
        self._stub_table_exists()
        self.ddb_stubber.add_response('put_item', {})
        holder = self.zappa.acquire_deployment_lock('myapp-dev')
        self.assertIn('@', holder)

    def test_acquire_blocked_by_other_holder_raises(self):
        self._stub_table_exists()
        self.ddb_stubber.add_client_error(
            'put_item',
            service_error_code='ConditionalCheckFailedException')
        self.ddb_stubber.add_response(
            'get_item',
            {'Item': {
                'lock_key': {'S': 'myapp-dev'},
                'holder': {'S': 'someone@host'},
                'acquired_at': {'N': '100'},
                'expires_at': {'N': str(100 + 900)}}})
        with self.assertRaises(DeploymentLockError) as ctx:
            self.zappa.acquire_deployment_lock('myapp-dev')
        self.assertIn('someone@host', str(ctx.exception))

    def test_expired_lock_is_stolen_atomically_by_condition(self):
        # DynamoDB evaluates 'attribute_not_exists OR expires_at < now'
        # server-side, so an expired row never causes a conditional failure:
        # the steal is a single successful put.
        self._stub_table_exists()
        self.ddb_stubber.add_response('put_item', {})
        holder = self.zappa.acquire_deployment_lock('myapp-dev')
        self.assertIn('@', holder)

    def test_wait_returns_error_message_with_expiry(self):
        self._stub_table_exists()
        self.ddb_stubber.add_client_error(
            'put_item',
            service_error_code='ConditionalCheckFailedException')
        future = 10 ** 11
        self.ddb_stubber.add_response(
            'get_item',
            {'Item': {
                'lock_key': {'S': 'myapp-dev'},
                'holder': {'S': 'dead@host'},
                'expires_at': {'N': str(future)}}})
        with self.assertRaises(DeploymentLockError) as ctx:
            self.zappa.acquire_deployment_lock('myapp-dev')
        message = str(ctx.exception)
        self.assertIn('dead@host', message)
        self.assertIn('expires in', message)

    def test_acquire_with_wait_retries_then_succeeds(self):
        self._stub_table_exists()
        # First attempt fails.
        self.ddb_stubber.add_client_error(
            'put_item',
            service_error_code='ConditionalCheckFailedException')
        self.ddb_stubber.add_response(
            'get_item',
            {'Item': {
                'lock_key': {'S': 'someone@host'},
                'expires_at': {'N': str(10 ** 11)}}})
        # Second polling attempt succeeds.
        self.ddb_stubber.add_response('put_item', {})
        with mock.patch('time.sleep'):
            holder = self.zappa.acquire_deployment_lock(
                'myapp-dev', wait_seconds=30, poll_interval=0)
        self.assertIn('@', holder)

    def test_release_only_when_owned(self):
        self.ddb_stubber.add_response('delete_item', {})
        self.zappa.release_deployment_lock(
            'myapp-dev', holder='me@host')

    def test_release_ignores_lost_lock(self):
        self.ddb_stubber.add_client_error(
            'delete_item',
            service_error_code='ConditionalCheckFailedException')
        # Must not raise.
        self.zappa.release_deployment_lock(
            'myapp-dev', holder='me@host')

    def test_table_auto_created_when_missing(self):
        self.ddb_stubber.add_client_error(
            'describe_table',
            service_error_code='ResourceNotFoundException')
        self.ddb_stubber.add_response(
            'create_table',
            {'TableDescription': {
                'TableName': DEPLOYMENT_LOCK_TABLE_NAME}})
        # table_exists waiter polls describe_table
        self.ddb_stubber.add_response(
            'describe_table',
            {'Table': {'TableName': DEPLOYMENT_LOCK_TABLE_NAME,
                       'TableStatus': 'ACTIVE'}})
        self.ddb_stubber.add_response('update_time_to_live', {})
        self.ddb_stubber.add_response('put_item', {})
        holder = self.zappa.acquire_deployment_lock('myapp-dev')
        self.assertTrue(holder)


class TestCLIDeploymentSafety(unittest.TestCase):
    def _make_cli(self):
        cli = ZappaCLI()
        cli.lambda_name = 'myapp-dev'
        cli.s3_bucket_name = 'bucket'
        cli.zip_path = '/tmp/pkg.zip'
        cli.deployment_lock_enabled = True
        cli.deployment_lock_timeout_seconds = 900
        cli.deployment_lock_wait_seconds = 0
        cli.zappa = mock.Mock()
        # Pre-create methods whose names start with 'assert_' - otherwise
        # Mock treats attribute access as an assertion call.
        cli.zappa.assert_lambda_function_exists = mock.Mock()
        cli.zappa.validate_iam_role.return_value = []
        cli.zappa.validate_deployer_permissions.return_value = []
        cli.zappa.acquire_deployment_lock.return_value = 'me@host'
        return cli

    # --- lock protection -------------------------------------------------

    def test_deploy_acquires_and_releases_lock(self):
        cli = self._make_cli()
        cli._deploy_impl = mock.Mock()
        cli.deploy()
        cli.zappa.acquire_deployment_lock.assert_called_once()
        self.assertEqual(
            cli.zappa.acquire_deployment_lock.call_args[1]['lock_key'],
            'myapp-dev')
        cli.zappa.release_deployment_lock.assert_called_once_with(
            'myapp-dev', holder='me@host')

    def test_lock_is_released_when_deploy_fails(self):
        cli = self._make_cli()
        cli._deploy_impl = mock.Mock(side_effect=RuntimeError('boom'))
        cli.zappa.cleanup_failed_deployment = mock.Mock()
        with self.assertRaises(ClickException):
            cli.deploy()
        cli.zappa.release_deployment_lock.assert_called_once()
        cli.zappa.cleanup_failed_deployment.assert_called_once()

    def test_concurrent_deploy_blocked(self):
        cli = self._make_cli()
        cli.zappa.acquire_deployment_lock.side_effect = \
            DeploymentLockError('another deployment in progress')
        cli._deploy_impl = mock.Mock()
        with self.assertRaises(ClickException) as ctx:
            cli.deploy()
        self.assertIn('another deployment in progress', str(ctx.exception))
        # Body must never run, and no release attempted.
        cli._deploy_impl.assert_not_called()
        cli.zappa.release_deployment_lock.assert_not_called()

    def test_lock_can_be_disabled(self):
        cli = self._make_cli()
        cli.deployment_lock_enabled = False
        cli._deploy_impl = mock.Mock()
        cli.deploy()
        cli.zappa.acquire_deployment_lock.assert_not_called()

    # --- half-finished cleanup ------------------------------------------

    def test_failed_deploy_cleans_up_created_lambda(self):
        cli = self._make_cli()

        def fail(**kwargs):
            cli._deployment_created_lambda = True
            raise RuntimeError('apigw exploded')

        cli._deploy_impl = fail
        cli.zappa.cleanup_failed_deployment = mock.Mock()
        with self.assertRaises(ClickException):
            cli.deploy()
        _, kwargs = cli.zappa.cleanup_failed_deployment.call_args
        self.assertTrue(kwargs['created_lambda'])
        self.assertEqual(kwargs['function_name'], 'myapp-dev')
        self.assertEqual(kwargs['bucket_name'], 'bucket')

    def test_failed_deploy_keeps_preexisting_lambda(self):
        cli = self._make_cli()
        cli._deployment_created_lambda = False
        cli._deploy_impl = mock.Mock(side_effect=RuntimeError('x'))
        cli.zappa.cleanup_failed_deployment = mock.Mock()
        with self.assertRaises(ClickException):
            cli.deploy()
        _, kwargs = cli.zappa.cleanup_failed_deployment.call_args
        self.assertFalse(kwargs['created_lambda'])

    # --- update auto-rollback -------------------------------------------

    def test_update_rolls_back_when_new_code_is_bad(self):
        cli = self._make_cli()
        cli._update_impl = mock.Mock(
            side_effect=RuntimeError('broken config'))
        # Simulate code was published before the failure.
        def impl(*a, **k):
            cli._update_code_published = True
            raise RuntimeError('broken config')
        cli._update_impl = impl
        cli.zappa.rollback_lambda_function_version.return_value = \
            'arn:aws:lambda:us-east-1:123:function:myapp-dev:9'
        with self.assertRaises(ClickException) as ctx:
            cli.update()
        self.assertIn('rolled back', str(ctx.exception))
        cli.zappa.rollback_lambda_function_version.assert_called_once_with(
            'myapp-dev', versions_back=1, restore_configuration=True)

    def test_update_no_rollback_when_code_not_published(self):
        cli = self._make_cli()
        cli._update_code_published = False
        cli._update_impl = mock.Mock(side_effect=RuntimeError('upload failed'))
        with self.assertRaises(ClickException) as ctx:
            cli.update()
        self.assertIn('not changed', str(ctx.exception))
        cli.zappa.rollback_lambda_function_version.assert_not_called()

    def test_update_preflight_missing_function(self):
        cli = self._make_cli()
        cli.zappa.assert_lambda_function_exists.side_effect = \
            LambdaFunctionNotFound('gone')
        cli._update_impl = mock.Mock()
        with self.assertRaises(ClickException):
            cli.update()
        cli._update_impl.assert_not_called()

    def test_update_auto_rollback_can_be_disabled(self):
        cli = self._make_cli()
        cli._update_impl = mock.Mock(side_effect=RuntimeError('x'))
        with self.assertRaises(RuntimeError):
            cli.update(auto_rollback=False)
        cli.zappa.rollback_lambda_function_version.assert_not_called()

    # --- full rollback command ------------------------------------------

    def test_rollback_command_restores_code_and_configuration(self):
        cli = self._make_cli()
        cli.zappa.rollback_lambda_function_version.return_value = \
            'arn:aws:lambda:us-east-1:123:function:myapp-dev:8'
        cli.rollback(2)
        cli.zappa.rollback_lambda_function_version.assert_called_once_with(
            'myapp-dev', versions_back=2, restore_configuration=True)

    def test_rollback_command_reports_insufficient_revisions(self):
        cli = self._make_cli()
        cli.zappa.rollback_lambda_function_version.return_value = False
        with self.assertRaises(ClickException):
            cli.rollback(5)

    def test_rollback_command_requires_existing_function(self):
        cli = self._make_cli()
        cli.zappa.assert_lambda_function_exists.side_effect = \
            LambdaFunctionNotFound('gone')
        with self.assertRaises(ClickException):
            cli.rollback(1)
        cli.zappa.rollback_lambda_function_version.assert_not_called()
