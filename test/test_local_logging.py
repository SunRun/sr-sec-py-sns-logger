import io
import json
import os
import sys
import unittest
from unittest.mock import patch

from security_log_fields import CloudEnvType, EventType, Status, AuthProtocol, ActorType, UserRole
from security_logging_sns import init_security_logging, log_user_login
from lambda_helpers import init_lambda_security_logging, reset_lambda_security_logging
from sns_publisher import SNSPublisher


class TestLocalLogging(unittest.TestCase):

    def setUp(self):
        # Clear local logging env vars if any
        for key in ["SR_SEC_LOG_TO_STDOUT", "SR_SEC_LOCAL_LOGGING", "SECURITY_LOGS_LOCAL_LOGGING"]:
            if key in os.environ:
                del os.environ[key]
        reset_lambda_security_logging()

    def tearDown(self):
        for key in ["SR_SEC_LOG_TO_STDOUT", "SR_SEC_LOCAL_LOGGING", "SECURITY_LOGS_LOCAL_LOGGING"]:
            if key in os.environ:
                del os.environ[key]
        reset_lambda_security_logging()

    def test_default_does_not_log_to_stdout(self):
        publisher = SNSPublisher(
            topic_arn="arn:aws:sns:us-west-2:123456789012:test-topic",
            test_mode=True
        )
        self.assertFalse(publisher.log_to_local_stdout)

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            publisher.publish_message({
                "event_type": "login_attempt",
                "status": "status.general.success",
                "actor_identifier": "test@sunrun.com"
            })

        self.assertEqual(captured_stdout.getvalue(), "")

    def test_log_to_local_stdout_flag_prints_json(self):
        publisher = SNSPublisher(
            topic_arn="arn:aws:sns:us-west-2:123456789012:test-topic",
            test_mode=True,
            log_to_local_stdout=True
        )
        self.assertTrue(publisher.log_to_local_stdout)

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            result = publisher.publish_message({
                "event_type": "login_attempt",
                "status": "status.general.success",
                "actor_identifier": "test@sunrun.com"
            })

        output = captured_stdout.getvalue().strip()
        self.assertTrue(len(output) > 0)
        parsed = json.loads(output)
        self.assertEqual(parsed.get("event_type"), "login_attempt")
        self.assertEqual(parsed.get("actor_identifier"), "test@sunrun.com")
        self.assertEqual(result["status"], "success")

    def test_local_logging_alias_flag_prints_json(self):
        publisher = SNSPublisher(
            topic_arn="arn:aws:sns:us-west-2:123456789012:test-topic",
            test_mode=True,
            local_logging=True
        )
        self.assertTrue(publisher.log_to_local_stdout)

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            publisher.publish_message({
                "event_type": "mfa_challenge",
                "status": "status.general.success"
            })

        output = captured_stdout.getvalue().strip()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("event_type"), "mfa_challenge")

    def test_env_var_enables_local_logging(self):
        os.environ["SR_SEC_LOG_TO_STDOUT"] = "true"
        publisher = SNSPublisher(
            topic_arn="arn:aws:sns:us-west-2:123456789012:test-topic",
            test_mode=True
        )
        self.assertTrue(publisher.log_to_local_stdout)

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            publisher.publish_message({
                "event_type": "api_request",
                "status": "status.general.success"
            })

        output = captured_stdout.getvalue().strip()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("event_type"), "api_request")

    def test_init_security_logging_with_local_logging(self):
        init_security_logging(
            test_mode=True,
            cloud_env_type=CloudEnvType.DEV,
            cloud_env_unique_id="123456789012",
            cloud_env_name="dev",
            service_account_id="arn:aws:iam::123456789012:role/test",
            service_name="test-service",
            log_to_local_stdout=True
        )

        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            log_user_login(
                cloud_env_type=CloudEnvType.DEV,
                cloud_env_unique_id="123456789012",
                cloud_env_name="dev",
                service_account_id="arn:aws:iam::123456789012:role/test",
                service_name="test-service",
                event_type=EventType.LOGIN_ATTEMPT,
                status=Status.SUCCESS,
                auth_protocol=AuthProtocol.OAUTH2_JWT,
                user_agent="pytest-agent",
                user_role=UserRole.ADMIN,
                actor_identifier="user@sunrun.com",
                actor_type=ActorType.HUMAN_INTERNAL,
                session_id="sess_123"
            )

        output = captured_stdout.getvalue().strip()
        self.assertTrue(len(output) > 0)
        parsed = json.loads(output)
        self.assertEqual(parsed.get("event_type"), EventType.LOGIN_ATTEMPT)
        self.assertEqual(parsed.get("actor_identifier"), "user@sunrun.com")
        self.assertEqual(parsed.get("service_name"), "test-service")

    def test_init_lambda_security_logging_with_local_logging(self):
        from lambda_helpers import build_lambda_context
        os.environ["ENV_NAME"] = "staging"
        init_lambda_security_logging(
            service_name="test-lambda",
            envs=[{
                "names": ["staging"],
                "cloud_env_type": CloudEnvType.STAGE,
                "cloud_env_name": "staging",
                "account_id": "999888777666",
            }],
            default_account_id="111222333444",
            test_mode=True,
            log_to_local_stdout=True
        )

        event = {"headers": {"x-forwarded-for": "198.51.100.4", "user-agent": "pytest"}}
        captured_stdout = io.StringIO()
        with patch("sys.stdout", captured_stdout):
            log_user_login(
                event_type=EventType.LOGIN_ATTEMPT,
                status=Status.SUCCESS,
                auth_protocol=AuthProtocol.OAUTH2_JWT,
                **build_lambda_context(event, pre_session=True, identity={"email": "lambda_user@sunrun.com"})
            )

        output = captured_stdout.getvalue().strip()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("actor_identifier"), "lambda_user@sunrun.com")
        self.assertEqual(parsed.get("service_name"), "test-lambda")
        self.assertEqual(parsed.get("cloud_env_unique_id"), "999888777666")


if __name__ == "__main__":
    unittest.main()
