"""
API Gateway Lambda helpers.

Apps pass service name and env/account mapping. This module does not
hardcode any application's accounts or env names.
"""

import logging
import os
from typing import Any, Callable, Dict, List, Optional

from context_helpers import extract_session_id, extract_source_ip, extract_user_agent
from security_log_fields import ActorType, CloudEnvType, UserRole
from security_logging_sns import (
    get_environment_config,
    init_security_logging,
    set_security_logging_error_handler,
)

_logger = logging.getLogger("security_logging")
_initialized = False
_DEFAULT_ENV_VARS = ("ENV_NAME", "ENV", "envName")


def reset_lambda_security_logging() -> None:
    global _initialized
    _initialized = False


def _read_env_name(names: List[str]) -> str:
    for name in names:
        value = os.environ.get(name)
        if isinstance(value, str) and value:
            return value
    return ""


def _resolve_account_id(fallback: str) -> str:
    return os.environ.get("awsAccountId") or os.environ.get("AWS_ACCOUNT_ID") or fallback


def _looks_like_email(value: Any) -> bool:
    return isinstance(value, str) and "@" in value and len(value) < 320 and " " not in value


def _email_from(record: Any, *keys: str) -> Optional[str]:
    if not isinstance(record, dict):
        return None
    for key in keys:
        value = record.get(key)
        if _looks_like_email(value):
            return value
    return None


def init_lambda_security_logging(
    service_name: str,
    envs: List[Dict[str, Any]],
    default_account_id: str,
    env_var_names: Optional[List[str]] = None,
    region: str = "us-west-2",
    test_mode: bool = False,
) -> None:
    """Initialize logging once per process. awsAccountId / AWS_ACCOUNT_ID override the mapped account."""
    global _initialized
    if _initialized:
        return
    _initialized = True

    raw_name = _read_env_name(list(env_var_names or _DEFAULT_ENV_VARS))
    match = next((env for env in envs if raw_name in env.get("names", [])), None)
    account_id = _resolve_account_id((match or {}).get("account_id") or default_account_id)
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or service_name

    init_security_logging(
        test_mode=test_mode,
        cloud_env_type=(match or {}).get("cloud_env_type") or CloudEnvType.DEV,
        cloud_env_unique_id=account_id,
        cloud_env_name=(match or {}).get("cloud_env_name") or (raw_name or "local"),
        service_account_id="arn:aws:lambda:{0}:{1}:function:{2}".format(region, account_id, function_name),
        service_name=service_name,
    )

    def _on_error(error_msg: str, event_type: Optional[str] = None) -> None:
        _logger.error("Failed to log %s: %s", event_type or "unknown", error_msg)

    set_security_logging_error_handler(_on_error)


def ignore_log_error(action: Callable[[], Any]) -> Any:
    """Run a logging call. A bad signature or publish error must not fail the handler."""
    try:
        return action()
    except Exception:
        return None


def extract_failure_reason(error: Any) -> str:
    """Use the exception type name only. Never str(error), which can contain customer data."""
    if not error:
        return "unknown_error"
    if isinstance(error, BaseException):
        return type(error).__name__ or "Error"
    return "unknown_error"


def extract_api_gateway_source_ip(event: Optional[Dict[str, Any]]) -> str:
    return extract_source_ip(event) or "unknown"


def extract_api_gateway_user_agent(event: Optional[Dict[str, Any]]) -> str:
    return extract_user_agent(event) or "unknown"


def actor_from_resolved_identity(identity: Any) -> str:
    """Actor is an email the handler already resolved. Never a token claim and never the request body."""
    if not isinstance(identity, dict):
        return "unknown"
    impersonator = _email_from(identity.get("impersonator"), "email")
    if impersonator:
        return impersonator
    demo_user = _email_from(identity.get("demoUser") or identity.get("demo_user"), "email")
    if demo_user:
        return demo_user
    email = _email_from(
        identity,
        "email",
        "sfdcEmail",
        "sfdc_email",
        "cognitoEmail",
        "cognito_email",
        "authenticatedEmail",
        "authenticated_email",
    )
    if email:
        return email
    cognito = identity.get("cognitoUserData") or identity.get("cognito_user_data")
    return _email_from(cognito, "email") or "unknown"


def _session_id_from_identity(identity: Any) -> str:
    if not isinstance(identity, dict):
        return "unknown"
    user = identity.get("user") if isinstance(identity.get("user"), dict) else {}
    email = _email_from(identity, "email") or _email_from(user, "email")
    expires = identity.get("exp")
    if expires is None:
        expires = user.get("exp")
    if expires is None:
        expires = identity.get("expires")
    if not email or expires is None or expires == "":
        return "unknown"
    return extract_session_id({"user": {"email": email}, "expires": str(expires)}) or "unknown"


def build_lambda_context(event: Optional[Dict[str, Any]], **opts: Any) -> Dict[str, str]:
    """Shared log fields for one API Gateway event. Domain-specific builders stay in the app."""
    if opts.get("pre_session"):
        session_id = "pre_session"
    elif opts.get("session_id"):
        session_id = opts["session_id"]
    else:
        session_id = _session_id_from_identity(opts.get("identity"))
    identity = opts.get("identity")
    env = get_environment_config()
    return {
        "cloud_env_type": env.get("cloud_env_type") or "",
        "cloud_env_unique_id": env.get("cloud_env_unique_id") or "",
        "cloud_env_name": env.get("cloud_env_name") or "",
        "service_account_id": env.get("service_account_id") or "",
        "service_name": env.get("service_name") or "",
        "actor_identifier": opts.get("actor_identifier")
        or (actor_from_resolved_identity(identity) if identity else "unknown"),
        "actor_type": opts.get("actor_type") or ActorType.HUMAN_INTERNAL,
        "session_id": session_id,
        "source_ip_address": extract_api_gateway_source_ip(event),
        "user_agent": extract_api_gateway_user_agent(event),
        "user_role": opts.get("user_role") or UserRole.NOT_AVAILABLE,
    }
