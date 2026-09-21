# -*- coding: utf8 -*-
"""
Unit tests for the Zappa deployment-safety features:

  * deploy_api_gateway pre-flight checks (Lambda exists, IAM role is
    assumable and has the minimum permissions, REST API exists) and
    automatic cleanup of half-created gateway resources on failure.
  * rollback_lambda_function_version restoring both code and configuration.
  * The S3-backed cross-machine deployment lock used by the CLI.

These tests are fully mocked and require no AWS account or network access.
"""
import json
import time

import botocore
import mock
import unittest
from botocore.exceptions import ClientError

from zappa.core import (Zappa, ALB_LAMBDA_ALIAS, DeploymentLockError,
                        DEPLOYMENT_LOCK_PREFIX)
from zappa.cli import ZappaCLI


def make_client_error(code):
    return ClientError({'Error': {'Code': code, 'Message': code}}, 'called')


def make_zappa():
    session = mock.Mock()
    session.region_name = 'us-east-1'
    z = Zappa(
        boto_session=session,
        profile_name="test",
        aws_region="us-east-1",
        load_credentials=False,
    )
    z.lambda_client = mock.Mock()
    z.apigateway_client = mock.Mock()
    z.iam_client = mock.Mock()
    z.iam = mock.Mock()
    z.s3_client = mock.Mock()
    return z


class TestPreflightChecks(unittest.TestCase):
    ##
    # lambda_function_exists
    ##

    def test_lambda_function_exists_true(self):
        z = make_zappa()
        z.lambda_client.get_function.return_value = {
            'Configuration': {'FunctionArn': 'arn:aws:lambda:::function:f'}}
        self.assertTrue(z.lambda_function_exists('f'))
        z.lambda_client.get_function.assert_called_once_with(FunctionName='f')

    def test_lambda_function_exists_false(self):
        z = make_zappa()
        z.lambda_client.get_function.side_effect = make_client_error(
            'ResourceNotFoundException')
        self.assertFalse(z.lambda_function_exists('missing'))

    def test_lambda_function_exists_other_error_propagates(self):
        z = make_zappa()
        z.lambda_client.get_function.side_effect = make_client_error(
            'AccessDeniedException')
        with self.assertRaises(ClientError):
            z.lambda_function_exists('f')

    ##
    # validate_iam_role_for_lambda
    ##

    def _role(self):
        role = mock.Mock()
        role.assume_role_policy_document = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': ['lambda.amazonaws.com']}
            }]
        }
        return role

    def _paginator(self, decisions):
        paginator = mock.Mock()
        paginator.paginate.return_value = [{
            'EvaluationResults': [
                {'EvalActionName': action, 'EvalDecision': decision}
                for action, decision in decisions
            ]
        }]
        return paginator

    def test_validate_iam_role_ok(self):
        z = make_zappa()
        z.iam.Role.return_value = self._role()
        actions = ['logs:CreateLogGroup', 'logs:CreateLogStream',
                   'logs:PutLogEvents', 'lambda:InvokeFunction']
        z.iam_client.get_paginator.return_value = self._paginator(
            [(a, 'allowed') for a in actions])

        arn = 'arn:aws:iam::1234:role/ZappaLambdaExecution'
        self.assertTrue(z.validate_iam_role_for_lambda(arn))
        z.iam_client.get_paginator.assert_called_once_with(
            'simulate_principal_policy')

    def test_validate_iam_role_missing(self):
        z = make_zappa()
        role = self._role()
        role.load.side_effect = make_client_error('NoSuchEntity')
        z.iam.Role.return_value = role
        with self.assertRaises(EnvironmentError) as ctx:
            z.validate_iam_role_for_lambda('arn:aws:iam::1:role/Role')
        self.assertIn('does not exist', str(ctx.exception))

    def test_validate_iam_role_not_assumable(self):
        z = make_zappa()
        role = self._role()
        role.assume_role_policy_document = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {'Service': ['ec2.amazonaws.com']}
            }]
        }
        z.iam.Role.return_value = role
        with self.assertRaises(EnvironmentError) as ctx:
            z.validate_iam_role_for_lambda('arn:aws:iam::1:role/Role')
        self.assertIn('cannot be assumed by Lambda', str(ctx.exception))

    def test_validate_iam_role_missing_permission(self):
        z = make_zappa()
        z.iam.Role.return_value = self._role()
        decisions = [
            ('logs:CreateLogGroup', 'allowed'),
            ('logs:CreateLogStream', 'allowed'),
            ('logs:PutLogEvents', 'implicitDeny'),
            ('lambda:InvokeFunction', 'allowed'),
        ]
        z.iam_client.get_paginator.return_value = self._paginator(decisions)
        with self.assertRaises(EnvironmentError) as ctx:
            z.validate_iam_role_for_lambda('arn:aws:iam::1:role/Role')
        self.assertIn('logs:PutLogEvents', str(ctx.exception))

    def test_validate_iam_role_simulation_access_denied_skips(self):
        z = make_zappa()
        z.iam.Role.return_value = self._role()
        paginator = mock.Mock()
        paginator.paginate.side_effect = make_client_error('AccessDenied')
        z.iam_client.get_paginator.return_value = paginator
        # Must not raise: deploying credentials can't simulate policies.
        self.assertTrue(z.validate_iam_role_for_lambda('arn:aws:iam::1:role/Role'))

    ##
    # validate_deployment_prerequisites
    ##

    def test_prerequisites_ok(self):
        z = make_zappa()
        z.lambda_client.get_function.return_value = {'Configuration': {}}
        z.iam.Role.return_value = self._role()
        actions = ['logs:CreateLogGroup', 'logs:CreateLogStream',
                   'logs:PutLogEvents', 'lambda:InvokeFunction']
        z.iam_client.get_paginator.return_value = self._paginator(
            [(a, 'allowed') for a in actions])
        z.credentials_arn = 'arn:aws:iam::1:role/Role'
        z.apigateway_client.get_rest_api.return_value = {'id': 'api123'}

        self.assertTrue(z.validate_deployment_prerequisites('f', api_id='api123'))
        z.apigateway_client.get_rest_api.assert_called_once_with(
            restApiId='api123')

    def test_prerequisites_missing_lambda(self):
        z = make_zappa()
        z.lambda_client.get_function.side_effect = make_client_error(
            'ResourceNotFoundException')
        with self.assertRaises(EnvironmentError) as ctx:
            z.validate_deployment_prerequisites('missing', api_id='api')
        self.assertIn("does not exist", str(ctx.exception))
        # No gateway interaction when the Lambda check fails.
        z.apigateway_client.get_rest_api.assert_not_called()

    def test_prerequisites_missing_api(self):
        z = make_zappa()
        z.lambda_client.get_function.return_value = {'Configuration': {}}
        z.iam.Role.return_value = self._role()
        actions = ['logs:CreateLogGroup', 'logs:CreateLogStream',
                   'logs:PutLogEvents', 'lambda:InvokeFunction']
        z.iam_client.get_paginator.return_value = self._paginator(
            [(a, 'allowed') for a in actions])
        z.credentials_arn = 'arn:aws:iam::1:role/Role'
        z.apigateway_client.get_rest_api.side_effect = make_client_error(
            'NotFoundException')
        with self.assertRaises(ClientError):
            z.validate_deployment_prerequisites('f', api_id='missing')


class TestDeployApiGateway(unittest.TestCase):
    def _passing_preflight(self, z):
        z.lambda_client.get_function.return_value = {'Configuration': {}}
        role = mock.Mock()
        role.assume_role_policy_document = {
            'Statement': [{'Effect': 'Allow',
                           'Principal': {'Service': ['lambda.amazonaws.com']}}]
        }
        z.iam.Role.return_value = role
        actions = ['logs:CreateLogGroup', 'logs:CreateLogStream',
                   'logs:PutLogEvents', 'lambda:InvokeFunction']
        paginator = mock.Mock()
        paginator.paginate.return_value = [{
            'EvaluationResults': [
                {'EvalActionName': a, 'EvalDecision': 'allowed'}
                for a in actions]
        }]
        z.iam_client.get_paginator.return_value = paginator
        z.credentials_arn = 'arn:aws:iam::1:role/Role'

    def test_success_new_stage(self):
        z = make_zappa()
        self._passing_preflight(z)
        z.apigateway_client.get_stage.side_effect = make_client_error(
            'NotFoundException')
        z.apigateway_client.create_deployment.return_value = {'id': 'd1'}

        url = z.deploy_api_gateway(api_id='api123', stage_name='dev',
                                   function_name='f-dev')
        self.assertEqual(
            url,
            'https://api123.execute-api.us-east-1.amazonaws.com/dev')
        z.apigateway_client.create_deployment.assert_called_once()
        z.apigateway_client.update_stage.assert_called_once()
        z.apigateway_client.delete_deployment.assert_not_called()
        z.apigateway_client.delete_stage.assert_not_called()

    def test_preflight_failure_blocks_deployment(self):
        z = make_zappa()
        z.lambda_client.get_function.side_effect = make_client_error(
            'ResourceNotFoundException')
        with self.assertRaises(EnvironmentError):
            z.deploy_api_gateway(api_id='api123', stage_name='dev',
                                 function_name='missing')
        z.apigateway_client.create_deployment.assert_not_called()
        z.apigateway_client.update_stage.assert_not_called()

    def test_create_failure_new_stage_cleans_up(self):
        z = make_zappa()
        self._passing_preflight(z)
        z.apigateway_client.get_stage.side_effect = make_client_error(
            'NotFoundException')
        z.apigateway_client.create_deployment.side_effect = make_client_error(
            'InternalServerErrorException')
        with self.assertRaises(ClientError):
            z.deploy_api_gateway(api_id='api123', stage_name='dev',
                                 function_name='f-dev')
        # No deployment was created, so nothing to delete beyond the error.
        z.apigateway_client.update_stage.assert_not_called()

    def test_update_stage_failure_new_stage_cleans_up(self):
        z = make_zappa()
        self._passing_preflight(z)
        z.apigateway_client.get_stage.side_effect = make_client_error(
            'NotFoundException')
        z.apigateway_client.create_deployment.return_value = {'id': 'd1'}
        z.apigateway_client.update_stage.side_effect = make_client_error(
            'BadRequestException')

        with self.assertRaises(ClientError):
            z.deploy_api_gateway(api_id='api123', stage_name='dev',
                                 function_name='f-dev')

        z.apigateway_client.delete_stage.assert_called_once_with(
            restApiId='api123', stageName='dev')
        z.apigateway_client.delete_deployment.assert_called_once_with(
            restApiId='api123', deploymentId='d1')

    def test_update_stage_failure_existing_stage_reverts(self):
        z = make_zappa()
        self._passing_preflight(z)
        z.apigateway_client.get_stage.return_value = {'deploymentId': 'd-old'}
        z.apigateway_client.create_deployment.return_value = {'id': 'd-new'}
        # Only the stage *configuration* call fails; the cleanup repoint call
        # must succeed so traffic returns to the previous deployment.
        z.apigateway_client.update_stage.side_effect = [
            make_client_error('BadRequestException'),
            {},
        ]

        with self.assertRaises(ClientError):
            z.deploy_api_gateway(api_id='api123', stage_name='dev',
                                 function_name='f-dev')

        # Existing stage must be repointed to the old deployment; the stage
        # itself must never be deleted.
        z.apigateway_client.delete_stage.assert_not_called()
        patch_call = z.apigateway_client.update_stage.call_args_list[1]
        self.assertEqual(patch_call[1]['patchOperations'], [{
            'op': 'replace', 'path': '/deploymentId', 'value': 'd-old'}])
        z.apigateway_client.delete_deployment.assert_called_once_with(
            restApiId='api123', deploymentId='d-new')

    def test_cleanup_disabled_propagates_without_delete(self):
        z = make_zappa()
        self._passing_preflight(z)
        z.apigateway_client.get_stage.side_effect = make_client_error(
            'NotFoundException')
        z.apigateway_client.create_deployment.return_value = {'id': 'd1'}
        z.apigateway_client.update_stage.side_effect = make_client_error(
            'BadRequestException')
        with self.assertRaises(ClientError):
            z.deploy_api_gateway(api_id='api123', stage_name='dev',
                                 function_name='f-dev',
                                 cleanup_on_failure=False)
        z.apigateway_client.delete_stage.assert_not_called()
        z.apigateway_client.delete_deployment.assert_not_called()


class TestRollbackLambda(unittest.TestCase):
    """rollback_lambda_function_version restores code AND configuration."""

    def _configuration(self, **overrides):
        conf = {
            'Runtime': 'python3.8',
            'Role': 'arn:aws:iam::1234:role/ZappaLambdaExecution',
            'Handler': 'handler.lambda_handler',
            'Description': 'old desc',
            'Timeout': 15,
            'MemorySize': 256,
            'Environment': {'Variables': {'FOO': 'BAR'}},
            'TracingConfig': {'Mode': 'PassThrough'},
            'Layers': [{'Arn': 'arn:aws:lambda:::layer:x:1'}],
            'VpcConfig': {
                'SubnetIds': ['subnet-1'],
                'SecurityGroupIds': ['sg-1'],
                'VpcId': 'vpc-1',
            },
            'KmsKeyArn': 'arn:aws:kms:::key/abc',
            'DeadLetterConfig': {'TargetArn': 'arn:aws:sqs:::dlq'},
        }
        conf.update(overrides)
        return conf

    def test_not_enough_revisions(self):
        z = make_zappa()
        z.lambda_client.list_versions_by_function.return_value = {
            'Versions': [{'Version': '$LATEST'}, {'Version': '1'}]
        }
        self.assertFalse(z.rollback_lambda_function_version('f', versions_back=1))

    def test_build_configuration_rollback_kwargs_full(self):
        z = make_zappa()
        kwargs = z._build_configuration_rollback_kwargs('f', self._configuration())
        self.assertEqual(kwargs['FunctionName'], 'f')
        self.assertEqual(kwargs['Runtime'], 'python3.8')
        self.assertEqual(kwargs['Role'],
                         'arn:aws:iam::1234:role/ZappaLambdaExecution')
        self.assertEqual(kwargs['Handler'], 'handler.lambda_handler')
        self.assertEqual(kwargs['Description'], 'old desc')
        self.assertEqual(kwargs['Timeout'], 15)
        self.assertEqual(kwargs['MemorySize'], 256)
        self.assertEqual(kwargs['Environment'], {'Variables': {'FOO': 'BAR'}})
        self.assertEqual(kwargs['TracingConfig'], {'Mode': 'PassThrough'})
        self.assertEqual(kwargs['Layers'], ['arn:aws:lambda:::layer:x:1'])
        self.assertEqual(sorted(kwargs['VpcConfig'].keys()),
                         ['SecurityGroupIds', 'SubnetIds'])
        self.assertEqual(kwargs['VpcConfig']['SubnetIds'], ['subnet-1'])
        self.assertEqual(kwargs['VpcConfig']['SecurityGroupIds'], ['sg-1'])
        self.assertEqual(kwargs['KMSKeyArn'], 'arn:aws:kms:::key/abc')
        self.assertEqual(kwargs['DeadLetterConfig'],
                         {'TargetArn': 'arn:aws:sqs:::dlq'})

    def test_build_configuration_rollback_kwargs_minimal(self):
        z = make_zappa()
        conf = self._configuration()
        del conf['VpcConfig']
        del conf['KmsKeyArn']
        del conf['DeadLetterConfig']
        conf['Layers'] = []
        kwargs = z._build_configuration_rollback_kwargs('f', conf)
        self.assertNotIn('VpcConfig', kwargs)
        self.assertNotIn('KMSKeyArn', kwargs)
        self.assertNotIn('DeadLetterConfig', kwargs)
        self.assertEqual(kwargs['Layers'], [])
        self.assertEqual(kwargs['Environment'], {'Variables': {'FOO': 'BAR'}})

    def test_full_rollback_restores_code_configuration_and_alias(self):
        z = make_zappa()
        z.lambda_client.list_versions_by_function.return_value = {
            'Versions': [
                {'Version': '$LATEST'},
                {'Version': '2'},
                {'Version': '1'},
            ]
        }
        z.lambda_client.get_function.return_value = {
            'Configuration': self._configuration(),
            'Code': {'Location': 'https://example.com/code.zip'},
        }

        download = mock.Mock()
        download.status_code = 200
        download.content = b'zip-bytes'

        z.lambda_client.get_alias.return_value = {'Name': ALB_LAMBDA_ALIAS}
        z.lambda_client.update_function_code.return_value = {
            'FunctionArn': 'arn:aws:lambda:::function:f:3'}
        z.lambda_client.update_function_configuration.return_value = {
            'FunctionArn': 'arn:aws:lambda:::function:f:3'}
        z.lambda_client.publish_version.return_value = {
            'FunctionArn': 'arn:aws:lambda:::function:f:3',
            'Version': '3'}

        with mock.patch('zappa.core.requests.get', return_value=download):
            arn = z.rollback_lambda_function_version('f', versions_back=1)

        self.assertEqual(arn, 'arn:aws:lambda:::function:f:3')

        # get_function targeted the previous version (revision 1).
        self.assertEqual(
            z.lambda_client.get_function.call_args[1],
            {'FunctionName': 'f', 'Qualifier': '1'})

        # Code restored from the historical download.
        code_kwargs = z.lambda_client.update_function_code.call_args[1]
        self.assertEqual(code_kwargs['ZipFile'], b'zip-bytes')
        self.assertEqual(code_kwargs['FunctionName'], 'f')

        # Configuration fully restored.
        cfg_kwargs = z.lambda_client.update_function_configuration.call_args[1]
        self.assertEqual(cfg_kwargs['Runtime'], 'python3.8')
        self.assertEqual(cfg_kwargs['Timeout'], 15)
        self.assertEqual(cfg_kwargs['MemorySize'], 256)
        self.assertEqual(cfg_kwargs['Environment'],
                         {'Variables': {'FOO': 'BAR'}})
        self.assertEqual(cfg_kwargs['Layers'],
                         ['arn:aws:lambda:::layer:x:1'])
        self.assertEqual(cfg_kwargs['VpcConfig'],
                         {'SubnetIds': ['subnet-1'],
                          'SecurityGroupIds': ['sg-1']})

        # ALB alias moved back to the rolled-back revision.
        z.lambda_client.update_alias.assert_called_once_with(
            FunctionName='f', FunctionVersion='1', Name=ALB_LAMBDA_ALIAS)

        # Final snapshot publish.
        z.lambda_client.publish_version.assert_called_once_with(
            FunctionName='f')

    def test_rollback_no_alias_does_not_update_alias(self):
        z = make_zappa()
        z.lambda_client.list_versions_by_function.return_value = {
            'Versions': [
                {'Version': '$LATEST'},
                {'Version': '2'},
                {'Version': '1'},
            ]
        }
        z.lambda_client.get_function.return_value = {
            'Configuration': self._configuration(),
            'Code': {'Location': 'https://example.com/code.zip'},
        }
        download = mock.Mock()
        download.status_code = 200
        download.content = b'zip-bytes'
        z.lambda_client.get_alias.side_effect = make_client_error(
            'ResourceNotFoundException')
        z.lambda_client.update_function_code.return_value = {
            'FunctionArn': 'arn:aws:lambda:::function:f:2'}
        z.lambda_client.publish_version.return_value = {
            'FunctionArn': 'arn:aws:lambda:::function:f:2', 'Version': '2'}

        with mock.patch('zappa.core.requests.get', return_value=download):
            arn = z.rollback_lambda_function_version('f', versions_back=1)

        self.assertTrue(arn)
        z.lambda_client.update_alias.assert_not_called()

    def test_rollback_download_failure_returns_false(self):
        z = make_zappa()
        z.lambda_client.list_versions_by_function.return_value = {
            'Versions': [
                {'Version': '$LATEST'},
                {'Version': '2'},
                {'Version': '1'},
            ]
        }
        z.lambda_client.get_function.return_value = {
            'Configuration': self._configuration(),
            'Code': {'Location': 'https://example.com/code.zip'},
        }
        download = mock.Mock()
        download.status_code = 403
        with mock.patch('zappa.core.requests.get', return_value=download):
            self.assertFalse(
                z.rollback_lambda_function_version('f', versions_back=1))
        z.lambda_client.update_function_code.assert_not_called()
        z.lambda_client.update_function_configuration.assert_not_called()

    def test_conflict_retry_succeeds_after_retries(self):
        z = make_zappa()
        method = mock.Mock(side_effect=[
            make_client_error('ResourceConflictException'),
            make_client_error('ResourceConflictException'),
            'ok',
        ])
        with mock.patch('zappa.core.time.sleep'):
            result = z._call_lambda_with_conflict_retry(
                method, FunctionName='f')
        self.assertEqual(result, 'ok')
        self.assertEqual(method.call_count, 3)

    def test_conflict_retry_reraises_other_errors(self):
        z = make_zappa()
        method = mock.Mock(side_effect=make_client_error('AccessDeniedException'))
        with self.assertRaises(ClientError):
            z._call_lambda_with_conflict_retry(method, FunctionName='f')
        method.assert_called_once()


class TestDeploymentLock(unittest.TestCase):
    def _s3_not_found(self):
        return make_client_error('NoSuchKey')

    def test_lock_key_format(self):
        z = make_zappa()
        self.assertEqual(
            z.deployment_lock_key('f-dev'),
            '{}-f-dev'.format(DEPLOYMENT_LOCK_PREFIX))

    def test_acquire_lock_when_free(self):
        z = make_zappa()
        z.s3_client.get_object.side_effect = self._s3_not_found()
        acquired = z.acquire_deployment_lock('bucket', 'f-dev',
                                             holder='alice@host', ttl=60)
        self.assertTrue(acquired)
        put_kwargs = z.s3_client.put_object.call_args[1]
        self.assertEqual(put_kwargs['Bucket'], 'bucket')
        self.assertEqual(put_kwargs['Key'],
                         '{}-f-dev'.format(DEPLOYMENT_LOCK_PREFIX))
        self.assertEqual(put_kwargs['IfNoneMatch'], '*')
        payload = json.loads(put_kwargs['Body'].decode('utf-8'))
        self.assertEqual(payload['holder'], 'alice@host')
        self.assertEqual(payload['function'], 'f-dev')
        self.assertIn('acquired_at', payload)

    def test_acquire_lock_blocked_by_active_holder(self):
        z = make_zappa()
        body = mock.Mock()
        body.read.return_value = json.dumps({
            'holder': 'bob@otherhost',
            'acquired_at': int(time.time()),
        }).encode('utf-8')
        z.s3_client.get_object.return_value = {'Body': body}

        with self.assertRaises(DeploymentLockError) as ctx:
            z.acquire_deployment_lock('bucket', 'f-dev',
                                      holder='alice@host', ttl=3600)
        self.assertIn('bob@otherhost', str(ctx.exception))
        z.s3_client.put_object.assert_not_called()

    def test_acquire_lock_takes_over_stale_lock(self):
        z = make_zappa()
        body = mock.Mock()
        body.read.return_value = json.dumps({
            'holder': 'bob@dead-host',
            'acquired_at': int(time.time()) - 7200,
        }).encode('utf-8')
        z.s3_client.get_object.return_value = {'Body': body}

        acquired = z.acquire_deployment_lock('bucket', 'f-dev',
                                             holder='alice@host', ttl=3600)
        self.assertTrue(acquired)
        z.s3_client.put_object.assert_called_once()

    def test_acquire_lost_race_raises(self):
        z = make_zappa()
        z.s3_client.get_object.side_effect = self._s3_not_found()
        z.s3_client.put_object.side_effect = make_client_error(
            'PreconditionFailed')
        with self.assertRaises(DeploymentLockError):
            z.acquire_deployment_lock('bucket', 'f-dev', holder='alice')

    def test_release_deletes_only_held_lock(self):
        z = make_zappa()
        # Never acquired -> must not delete someone else's lock.
        self.assertFalse(z.release_deployment_lock('bucket', 'f-dev'))
        z.s3_client.delete_object.assert_not_called()

        z.s3_client.get_object.side_effect = self._s3_not_found()
        z.acquire_deployment_lock('bucket', 'f-dev', holder='alice')
        self.assertTrue(z.release_deployment_lock('bucket', 'f-dev'))
        z.s3_client.delete_object.assert_called_once_with(
            Bucket='bucket', Key='{}-f-dev'.format(DEPLOYMENT_LOCK_PREFIX))

        # Second release is a no-op.
        z.s3_client.reset_mock()
        self.assertFalse(z.release_deployment_lock('bucket', 'f-dev'))
        z.s3_client.delete_object.assert_not_called()

    def test_disabled_lock_is_noop(self):
        z = make_zappa()
        z.deployment_lock_enabled = False
        self.assertFalse(z.acquire_deployment_lock('bucket', 'f-dev'))
        self.assertFalse(z.release_deployment_lock('bucket', 'f-dev'))
        z.s3_client.get_object.assert_not_called()
        z.s3_client.put_object.assert_not_called()


class TestCLIDeploymentLock(unittest.TestCase):
    """The CLI wraps mutating commands with the deployment lock."""

    def _cli(self):
        cli = ZappaCLI.__new__(ZappaCLI)
        cli.zappa = mock.Mock()
        cli.zappa.deployment_lock_enabled = True
        cli.s3_bucket_name = 'bucket'
        cli.lambda_name = 'f-dev'
        return cli

    def test_acquire_or_exit_success(self):
        cli = self._cli()
        cli.acquire_deployment_lock_or_exit()
        cli.zappa.acquire_deployment_lock.assert_called_once_with(
            bucket_name='bucket', function_name='f-dev')

    def test_acquire_or_exit_exits_when_locked(self):
        cli = self._cli()
        cli.zappa.acquire_deployment_lock.side_effect = DeploymentLockError(
            'locked by bob')
        with self.assertRaises(SystemExit):
            cli.acquire_deployment_lock_or_exit()

    def test_release_delegates(self):
        cli = self._cli()
        cli.release_deployment_lock()
        cli.zappa.release_deployment_lock.assert_called_once_with(
            bucket_name='bucket', function_name='f-dev')

    def test_disabled_lock_is_cli_noop(self):
        cli = self._cli()
        cli.zappa.deployment_lock_enabled = False
        cli.acquire_deployment_lock_or_exit()
        cli.release_deployment_lock()
        cli.zappa.acquire_deployment_lock.assert_not_called()
        cli.zappa.release_deployment_lock.assert_not_called()

    def test_deploy_wraps_with_lock_and_releases_on_success(self):
        cli = self._cli()
        cli._deploy_locked = mock.Mock()
        cli.deploy()
        cli.zappa.acquire_deployment_lock.assert_called_once()
        cli._deploy_locked.assert_called_once()
        cli.zappa.release_deployment_lock.assert_called_once()

    def test_deploy_releases_lock_when_deployment_raises(self):
        cli = self._cli()
        cli._deploy_locked = mock.Mock(side_effect=RuntimeError('boom'))
        with self.assertRaises(RuntimeError):
            cli.deploy()
        cli.zappa.acquire_deployment_lock.assert_called_once()
        cli.zappa.release_deployment_lock.assert_called_once()

    def test_update_wraps_with_lock(self):
        cli = self._cli()
        cli._update_locked = mock.Mock()
        cli.update(source_zip=None, no_upload=True)
        cli.zappa.acquire_deployment_lock.assert_called_once()
        cli._update_locked.assert_called_once_with(
            source_zip=None, no_upload=True)
        cli.zappa.release_deployment_lock.assert_called_once()

    def test_undeploy_wraps_with_lock(self):
        cli = self._cli()
        cli._undeploy_locked = mock.Mock()
        cli.undeploy(no_confirm=True, remove_logs=False)
        cli.zappa.acquire_deployment_lock.assert_called_once()
        cli._undeploy_locked.assert_called_once_with(
            no_confirm=True, remove_logs=False)
        cli.zappa.release_deployment_lock.assert_called_once()


if __name__ == '__main__':
    unittest.main()
