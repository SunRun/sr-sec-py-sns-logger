#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from lambda_helpers import (
    actor_from_resolved_identity,
    build_lambda_context,
    extract_failure_reason,
    ignore_log_error,
    init_lambda_security_logging,
    reset_lambda_security_logging,
)
from security_log_fields import AuthProtocol, CloudEnvType, EventType, Status, UserRole
from security_logging_sns import get_environment_config, log_user_login


BASE = {
    "service_name": "demo-service",
    "default_account_id": "111111111111",
    "test_mode": True,
    "envs": [
        {
            "names": ["production", "prod", "prd"],
            "cloud_env_type": CloudEnvType.PROD,
            "cloud_env_name": "production",
            "account_id": "222222222222",
        },
        {
            "names": ["staging", "stage", "stg"],
            "cloud_env_type": CloudEnvType.STAGE,
            "cloud_env_name": "staging",
            "account_id": "333333333333",
        },
    ],
}


class LambdaHelpersTest(unittest.TestCase):
    def setUp(self):
        reset_lambda_security_logging()
        for name in ("ENV_NAME", "ENV", "envName", "awsAccountId", "AWS_ACCOUNT_ID", "AWS_LAMBDA_FUNCTION_NAME"):
            os.environ.pop(name, None)

    def test_maps_env_name_to_account_and_service(self):
        os.environ["ENV_NAME"] = "production"
        os.environ["AWS_LAMBDA_FUNCTION_NAME"] = "demoFunction"
        init_lambda_security_logging(**BASE)
        self.assertEqual(get_environment_config(), {
            "cloud_env_type": CloudEnvType.PROD,
            "cloud_env_unique_id": "222222222222",
            "cloud_env_name": "production",
            "service_name": "demo-service",
            "service_account_id": "arn:aws:lambda:us-west-2:222222222222:function:demoFunction",
        })

    def test_aws_account_id_overrides_mapped_account(self):
        os.environ["envName"] = "staging"
        os.environ["awsAccountId"] = "999999999999"
        init_lambda_security_logging(**BASE)
        config = get_environment_config()
        self.assertEqual(config["cloud_env_unique_id"], "999999999999")
        self.assertEqual(config["cloud_env_type"], CloudEnvType.STAGE)

    def test_unknown_env_falls_back_to_dev(self):
        os.environ["ENV"] = "ephemeral"
        init_lambda_security_logging(**BASE)
        config = get_environment_config()
        self.assertEqual(config["cloud_env_type"], CloudEnvType.DEV)
        self.assertEqual(config["cloud_env_unique_id"], "111111111111")
        self.assertEqual(config["cloud_env_name"], "ephemeral")

    def test_init_is_idempotent(self):
        os.environ["ENV_NAME"] = "staging"
        init_lambda_security_logging(**BASE)
        os.environ["ENV_NAME"] = "production"
        init_lambda_security_logging(service_name="other", envs=BASE["envs"], default_account_id="111111111111", test_mode=True)
        config = get_environment_config()
        self.assertEqual(config["service_name"], "demo-service")
        self.assertEqual(config["cloud_env_type"], CloudEnvType.STAGE)

    def test_ignore_log_error_swallows_exception(self):
        def boom():
            raise RuntimeError("sns down")

        self.assertIsNone(ignore_log_error(boom))
        self.assertEqual(ignore_log_error(lambda: "ok"), "ok")

    def test_extract_failure_reason_uses_type_name_only(self):
        error = RuntimeError("detail leaked in message")
        self.assertEqual(extract_failure_reason(error), "RuntimeError")
        self.assertNotIn("leaked", extract_failure_reason(error))
        self.assertEqual(extract_failure_reason(None), "unknown_error")

    def test_actor_prefers_impersonator_email(self):
        self.assertEqual(actor_from_resolved_identity({
            "email": "user@example.com",
            "impersonator": {"email": "operator@example.com"},
        }), "operator@example.com")
        self.assertEqual(actor_from_resolved_identity({}), "unknown")

    def test_build_lambda_context_reads_gateway_event(self):
        event = {"headers": {"X-Forwarded-For": "10.1.1.1, 10.2.2.2", "User-Agent": "pytest"}}
        context = build_lambda_context(event, pre_session=True, identity={"email": "user@example.com", "exp": 1700000000})
        self.assertEqual(context["actor_identifier"], "user@example.com")
        self.assertEqual(context["session_id"], "pre_session")
        self.assertEqual(context["source_ip_address"], "10.1.1.1")
        self.assertEqual(context["user_agent"], "pytest")
        self.assertEqual(context["user_role"], UserRole.NOT_AVAILABLE)

    def test_build_lambda_context_hashes_email_and_expiry(self):
        context = build_lambda_context({}, identity={"email": "user@example.com", "exp": 1700000000})
        self.assertTrue(context["session_id"].startswith("sess_"))
        self.assertEqual(context["actor_identifier"], "user@example.com")

    def test_login_event_accepts_adapter_context(self):
        os.environ["ENV_NAME"] = "staging"
        init_lambda_security_logging(**BASE)
        event = {"headers": {"x-forwarded-for": "198.51.100.4", "user-agent": "pytest"}}
        error = ValueError("do not log this body")
        result = ignore_log_error(lambda: log_user_login(
            event_type=EventType.LOGIN_ATTEMPT,
            status=Status.FAILURE,
            auth_protocol=AuthProtocol.OAUTH2_JWT,
            detail=extract_failure_reason(error),
            **build_lambda_context(event, pre_session=True),
        ))
        self.assertEqual(result["status"], "success")
        self.assertTrue(result.get("test_mode"))


if __name__ == "__main__":
    unittest.main()
