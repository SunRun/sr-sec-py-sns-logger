# File: security_logging_sns.py
"""
Security Logging SNS Module

Main security logging module with all logging functions. Provides a standardized
way to log security events to AWS SNS for compliance and monitoring.

Features:
    - Hot start optimization (SNS client reused across invocations)
    - Automatic failover between primary and failover regions
    - Message batching for large payloads (SNS 256KB limit)
    - UUID generation for event correlation
    - Automatic caller context extraction (function name, file name)
    - Comprehensive validation with all errors reported at once

Example:
    >>> from security_logging_sns import init_security_logging, log_user_login
    >>> from security_log_fields import EventType, Status, ActorType, AuthProtocol, CloudEnvType
    >>> 
    >>> # Initialize once (typically at module level for Lambda)
    >>> init_security_logging()
    >>> 
    >>> # Log a successful login
    >>> result = log_user_login(
    ...     # Required base fields
    ...     cloud_env_type=CloudEnvType.PROD,
    ...     cloud_env_unique_id="123456789012",
    ...     cloud_env_name="production",
    ...     service_account_id="arn:aws:iam::123456789012:role/AuthService",
    ...     service_name="auth-service",
    ...     
    ...     # Required event fields
    ...     event_type=EventType.LOGIN_ATTEMPT,
    ...     status=Status.SUCCESS,
    ...     user_agent="Mozilla/5.0...",
    ...     user_role="role.classification.admin",
    ...     auth_protocol=AuthProtocol.OAUTH2_JWT,
    ...     
    ...     # Common fields
    ...     actor_identifier="user@company.com",
    ...     actor_type=ActorType.HUMAN_INTERNAL,
    ...     session_id="sess_abc123"
    ... )
"""

import os
import re
import sys
import inspect
import threading
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union, Callable
from concurrent.futures import ThreadPoolExecutor, Future
from security_log_fields import (
    Status, ActorType, LogCategory, EventType, AuthProtocol, Detail, MfaType,
    HttpMethod, CloudEnvType, CloudServiceApiType, DataSensitivityLevel,
    EndpointSensitivity, InviteStatus, UserRole, VALID_EVENT_TYPES
)
from sns_publisher import SNSPublisher

# Global SNS publisher instance - initialized once per application (HOT START)
_sns_publisher: Optional[SNSPublisher] = None

# Global error handler for fire-and-forget logging
_error_handler = None

# Global environment configuration set during initialization
# These values are automatically included in all log events
_env_config: Dict[str, str] = {}


def get_environment_config() -> Dict[str, str]:
    """
    Get the current environment configuration.
    Used internally to merge with log events.
    """
    return _env_config.copy()

# Common required fields for ALL security log events
COMMON_REQUIRED_FIELDS = [
    'cloud_env_type',      # Environment: "prod", "stage", "test", "dev"
    'cloud_env_unique_id', # Unique identifier (e.g., AWS account ID)
    'cloud_env_name',      # Human-readable name (e.g., "production-us-west-2")
    'service_account_id',  # Service account/IAM role identifier
    'service_name'         # Name of the service generating the log
]


def init_security_logging(
    topic_arn: str = None, 
    region_name: str = None,
    failover_topic_arn: str = None,
    failover_region: str = None,
    enable_failover: bool = True,
    test_mode: bool = False,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    aws_session_token: str = None,
    # Environment fields (set once, used in all logs)
    cloud_env_type: str = None,
    cloud_env_unique_id: str = None,
    cloud_env_name: str = None,
    service_account_id: str = None,
    service_name: str = None
):
    """
    Initialize the security logging module with optional multi-region failover.
    
    **HOT START**: This function creates a singleton SNSPublisher that is reused
    across all logging calls. For Lambda functions, call this outside the handler
    to benefit from container reuse.
    
    Args:
        topic_arn: Primary SNS Topic ARN. If None, uses default or SECURITY_LOGS_TOPIC_ARN env var
        region_name: Primary AWS region. If None, uses us-west-2
        failover_topic_arn: Failover SNS Topic ARN (optional)
        failover_region: Failover AWS region. If None, uses us-east-2
        enable_failover: Enable automatic failover (default: True)
        test_mode: If True, logs are printed to console instead of sent to SNS
        aws_access_key_id: Optional AWS access key ID for IAM User authentication
        aws_secret_access_key: Optional AWS secret access key for IAM User authentication  
        aws_session_token: Optional AWS session token for temporary credentials
        cloud_env_type: Cloud environment type (e.g., CloudEnvType.PROD). Set once, included in all logs.
        cloud_env_unique_id: Unique environment ID (e.g., AWS Account ID). Set once, included in all logs.
        cloud_env_name: Human-readable environment name (e.g., "production"). Set once, included in all logs.
        service_account_id: Service account ID (e.g., IAM role ARN). Set once, included in all logs.
        service_name: Service/application name (e.g., "cypress-ui"). Set once, included in all logs.
    
    Example:
        >>> # Basic initialization with environment config
        >>> init_security_logging(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::123456789012:role/my-role",
        ...     service_name="my-service"
        ... )
        
        >>> # With explicit SNS configuration
        >>> init_security_logging(
        ...     topic_arn="arn:aws:sns:us-west-2:123456789012:my-topic",
        ...     failover_topic_arn="arn:aws:sns:us-east-2:123456789012:my-failover-topic",
        ...     enable_failover=True,
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     service_name="my-service"
        ... )
        
        >>> # Lambda best practice - initialize outside handler
        >>> # At module level:
        >>> init_security_logging(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     service_name="my-lambda"
        ... )
        >>> 
        >>> def handler(event, context):
        ...     # Use logging functions (reuses existing SNS client + env config)
        ...     log_user_login(...)  # No need to pass cloud_env_type, service_name, etc.
    """
    global _sns_publisher, _env_config
    
    # Store environment configuration (automatically included in all logs)
    _env_config = {
        'cloud_env_type': cloud_env_type,
        'cloud_env_unique_id': cloud_env_unique_id,
        'cloud_env_name': cloud_env_name,
        'service_account_id': service_account_id,
        'service_name': service_name
    }
    # Remove None values
    _env_config = {k: v for k, v in _env_config.items() if v is not None}
    
    # Default production ARNs and regions
    DEFAULT_TOPIC_ARN = "arn:aws:sns:us-west-2:000576341507:sr-sec-logging-log-topic-prod"
    DEFAULT_FAILOVER_TOPIC_ARN = "arn:aws:sns:us-east-2:000576341507:sr-sec-logging-log-topic-failover-prod"
    DEFAULT_REGION = "us-west-2"
    DEFAULT_FAILOVER_REGION = "us-east-2"
    
    # Primary topic configuration
    if topic_arn is None:
        topic_arn = os.environ.get("SECURITY_LOGS_TOPIC_ARN")
        if not topic_arn:
            if test_mode:
                topic_arn = "arn:aws:sns:us-east-1:123456789012:test-security-logs"
            else:
                topic_arn = DEFAULT_TOPIC_ARN
    
    # Helper to extract region from SNS topic ARN (arn:aws:sns:REGION:account:topic)
    def extract_region_from_arn(arn: str) -> str:
        match = re.match(r'^arn:aws:sns:([^:]+):', arn)
        return match.group(1) if match else None
    
    # Primary region: prefer explicit > extract from ARN > env var > default
    if region_name is None and topic_arn:
        region_name = extract_region_from_arn(topic_arn)
    if region_name is None:
        region_name = os.environ.get("AWS_REGION")
        if not region_name:
            region_name = DEFAULT_REGION
    
    # Failover topic configuration
    if failover_topic_arn is None and enable_failover:
        failover_topic_arn = os.environ.get("SECURITY_LOGS_FAILOVER_TOPIC_ARN")
        if not failover_topic_arn and not test_mode:
            failover_topic_arn = DEFAULT_FAILOVER_TOPIC_ARN
    
    # Failover region: prefer explicit > extract from ARN > env var > default
    if failover_region is None and failover_topic_arn:
        failover_region = extract_region_from_arn(failover_topic_arn)
    if failover_region is None:
        failover_region = os.environ.get("SECURITY_LOGS_FAILOVER_REGION", DEFAULT_FAILOVER_REGION)
    
    _sns_publisher = SNSPublisher(
        topic_arn=topic_arn,
        region_name=region_name,
        failover_topic_arn=failover_topic_arn,
        failover_region=failover_region,
        enable_failover=enable_failover,
        test_mode=test_mode,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )


def _get_publisher() -> SNSPublisher:
    """Get the global SNS publisher instance."""
    if _sns_publisher is None:
        raise RuntimeError("Security logging not initialized. Call init_security_logging() first.")
    return _sns_publisher


def get_failover_metrics() -> Dict[str, int]:
    """
    Get current failover metrics for monitoring.
    
    Returns:
        Dictionary with metrics:
        - primary_success: Successful publishes to primary region
        - primary_failure: Failed publishes to primary region
        - failover_attempts: Number of times failover was attempted
        - failover_success: Successful publishes to failover region
        - failover_failure: Failed publishes to failover region
        - total_failures: Total failures across both regions
    
    Example:
        >>> metrics = get_failover_metrics()
        >>> print(f"Failover used: {metrics['failover_success']} times")
    """
    publisher = _get_publisher()
    return publisher.get_metrics()


def reset_failover_metrics():
    """Reset failover metrics counters. Useful for testing or periodic resets."""
    publisher = _get_publisher()
    publisher.reset_metrics()


# ==================================
# == Fire-and-Forget Functionality
# ==================================

def set_security_logging_error_handler(handler: Callable[[str, Optional[str]], None]) -> None:
    """
    Set a custom error handler for fire-and-forget logging failures.
    Use this to emit CloudWatch metrics, write to logs, etc.
    
    Args:
        handler: Function that takes (error_message, event_type) and handles the error
    
    Example:
        >>> def my_error_handler(error_msg, event_type):
        ...     print(f"Security logging failed for {event_type}: {error_msg}")
        ...     # Emit CloudWatch metric
        ...     cloudwatch.put_metric('SecurityLoggingFailure', 1, {'EventType': event_type})
        >>> 
        >>> set_security_logging_error_handler(my_error_handler)
    """
    global _error_handler
    _error_handler = handler


def fire_and_forget(log_future: Future[Dict[str, str]], event_type: Optional[str] = None) -> None:
    """
    Fire-and-forget wrapper for security logging functions.
    Does NOT block your application - runs asynchronously with error handling.
    
    Args:
        log_future: Future returned by ThreadPoolExecutor.submit() with a logging function
        event_type: Optional event type for error reporting context
    
    Example:
        >>> from concurrent.futures import ThreadPoolExecutor
        >>> 
        >>> with ThreadPoolExecutor() as executor:
        ...     future = executor.submit(log_user_login, 
        ...         event_type=EventType.LOGIN_ATTEMPT,
        ...         status=Status.SUCCESS,
        ...         # ... other parameters
        ...     )
        ...     fire_and_forget(future, EventType.LOGIN_ATTEMPT)
        >>> 
        >>> # Application continues immediately - not blocked by SNS!
    """
    def handle_result(future: Future) -> None:
        try:
            result = future.result()
            if result.get('status') == 'failure':
                error_msg = f"Security logging failed: {result.get('message')}"
                if _error_handler:
                    _error_handler(error_msg, event_type)
                else:
                    print(error_msg, file=sys.stderr)
        except Exception as error:
            error_msg = f"Security logging error: {str(error)}"
            if _error_handler:
                _error_handler(error_msg, event_type)
            else:
                print(error_msg, file=sys.stderr)
    
    log_future.add_done_callback(handle_result)


# ==================================
# == Caller Context Extraction
# ==================================

def _get_caller_context() -> Dict[str, str]:
    """
    Extract caller information (function name, file name) from stack trace.
    This provides automatic context about where the log was generated.
    
    Returns:
        Dict with caller_function and caller_file keys
    """
    try:
        # Walk up the stack to find the first frame outside this module
        for frame_info in inspect.stack():
            if 'security_logging_sns' not in frame_info.filename:
                filename = os.path.basename(frame_info.filename)
                function_name = frame_info.function
                return {
                    'caller_function': function_name,
                    'caller_file': filename
                }
    except Exception:
        pass
    return {}


# ==================================
# == Standardized Values Validation
# ==================================

def _get_valid_values_for_field(field_name: str) -> List[str]:
    """Get list of valid standardized values for a given field."""
    valid_values = {
        "event_type": VALID_EVENT_TYPES,
        "status": [Status.SUCCESS, Status.FAILURE],
        "actor_type": [
            ActorType.HUMAN_INTERNAL, ActorType.HUMAN_PARTNER, ActorType.HUMAN_CUSTOMER,
            ActorType.SERVICE_INTERNAL, ActorType.SERVICE_PARTNER, ActorType.SERVICE_CUSTOMER,
            ActorType.SYSTEM_SELF
        ],
        "log_category": [
            LogCategory.AUTHN_SESSION, LogCategory.AUTHZ_ACCESS, LogCategory.API_ENDPOINT_ACCESS,
            LogCategory.CUSTOMER_DATA_ACTIONS, LogCategory.KEY_CONFIG_CHANGES
        ],
        "cloud_env_type": [CloudEnvType.PROD, CloudEnvType.STAGE, CloudEnvType.TEST, CloudEnvType.DEV],
        "auth_protocol": [
            AuthProtocol.BASIC_AUTH, AuthProtocol.FORM_BASED,
            AuthProtocol.API_KEY, AuthProtocol.M2M_TOKEN, AuthProtocol.SESSION_COOKIE,
            AuthProtocol.OAUTH2_JWT, AuthProtocol.OAUTH2_CLIENT_CREDENTIALS,
            AuthProtocol.OAUTH2_AUTHORIZATION_CODE, AuthProtocol.OAUTH2_IMPLICIT, AuthProtocol.OAUTH2_PASSWORD_GRANT,
            AuthProtocol.SAML, AuthProtocol.OIDC, AuthProtocol.NONE
        ],
        "http_method": [
            HttpMethod.GET, HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH,
            HttpMethod.DELETE, HttpMethod.HEAD, HttpMethod.OPTIONS
        ],
        "endpoint_sensitivity": [
            EndpointSensitivity.PUBLIC, EndpointSensitivity.NON_PUBLIC, 
            EndpointSensitivity.CONFIDENTIAL, EndpointSensitivity.RESTRICTED
        ],
        "data_sensitivity_level": [
            DataSensitivityLevel.PUBLIC, DataSensitivityLevel.NON_PUBLIC, 
            DataSensitivityLevel.CONFIDENTIAL, DataSensitivityLevel.RESTRICTED
        ],
        "user_role": [
            UserRole.ADMIN, UserRole.SALES_REP, UserRole.CUSTOMER_SUPPORT,
            UserRole.PARTNER_ADMIN, UserRole.CUSTOMER_USER
        ],
        "invite_status": [InviteStatus.SENT, InviteStatus.ACCEPTED, InviteStatus.REVOKED, InviteStatus.EXPIRED],
        "mfa_type": [
            MfaType.SMS, MfaType.TOTP, MfaType.PUSH, MfaType.EMAIL,
            MfaType.OKTA_VERIFY, MfaType.AUTHENTICATOR_APP, MfaType.HARDWARE_TOKEN,
            MfaType.BIOMETRIC, MfaType.BACKUP_CODES
        ],
        "detail": [
            # Authentication failures
            Detail.INVALID_CREDENTIALS, Detail.ACCOUNT_LOCKED, Detail.IP_RESTRICTED,
            Detail.MFA_REQUIRED, Detail.POLICY_VIOLATION, Detail.CAPTCHA_FAILURE,
            Detail.TOKEN_EXPIRED, Detail.TOKEN_INVALID, Detail.UNAUTHORIZED_ACCESS, Detail.RATE_LIMIT_EXCEEDED,
            # Triggers
            Detail.USER_INITIATED, Detail.ADMIN_INITIATED, Detail.SYSTEM_AUTOMATED,
            Detail.SYSTEM_POLICY_VIOLATION, Detail.SESSION_TIMEOUT, Detail.CONCURRENT_SESSION, Detail.FAILED_ATTEMPTS_THRESHOLD,
            # System/Operational
            Detail.INTERNAL_ERROR, Detail.SERVICE_UNAVAILABLE, Detail.MAINTENANCE,
            Detail.INVALID_REQUEST, Detail.NOT_APPLICABLE,
            # API Key and Auth Mechanism Details
            Detail.API_KEY_CREATED, Detail.API_KEY_REVOKED, Detail.API_KEY_PERMISSIONS_MODIFIED,
            Detail.SSO_CONFIG_CREATED, Detail.SSO_CONFIG_MODIFIED, Detail.SSO_CONFIG_DELETED,
            Detail.LOCAL_AUTH_ENABLED, Detail.LOCAL_AUTH_DISABLED,
            # User Status Actions
            Detail.USER_DISABLED, Detail.USER_ENABLED, Detail.USER_DELETED, Detail.USER_LOCKED, Detail.USER_UNLOCKED,
            # Impersonation Actions
            Detail.IMPERSONATION_START, Detail.IMPERSONATION_STOP,
            # Customer Data Actions
            Detail.VIEW_LIST, Detail.MODIFY_CUSTOMER_DATA, Detail.EXPORT_REPORT, Detail.VIEW_RECORD, Detail.EDIT_RECORD,
            # MFA Actions
            Detail.MFA_DISABLED, Detail.MFA_ENABLED, Detail.NEW_MFA_DEVICE,
            # MFA Challenge failure reasons
            Detail.MFA_INVALID_CODE, Detail.MFA_EXPIRED_CODE, Detail.MFA_DEVICE_NOT_ENROLLED, Detail.MFA_TOO_MANY_ATTEMPTS,
            # Password Actions
            Detail.PASSWORD_CHANGE, Detail.PASSWORD_RESET,
            # Auth Mechanism Actions
            Detail.NEW_SSO_PROVIDER, Detail.ENABLE_LOCAL_AUTHN, Detail.DISABLE_SSO
        ]
    }
    return valid_values.get(field_name, [])


def _validate_standardized_field(field_name: str, field_value: str, allow_custom_for_detail: bool = False) -> Dict[str, Any]:
    """
    Validate that a field uses standardized values.
    
    Args:
        field_name: Name of the field to validate
        field_value: Value to validate
        allow_custom_for_detail: For detail field, allow custom text for success cases
    
    Returns:
        Dict with "valid" boolean and "message" if invalid
    """
    if not field_value or (isinstance(field_value, str) and field_value.strip() == ""):
        return {"valid": True}  # Empty values are handled by required field validation
    
    valid_values = _get_valid_values_for_field(field_name)
    if not valid_values:
        return {"valid": True}  # Field doesn't have standardized values
    
    # Special handling for detail field - allow custom text for success contexts
    if field_name == "detail" and allow_custom_for_detail:
        if field_value not in valid_values:
            return {"valid": True}
    
    if field_value not in valid_values:
        return {
            "valid": False,
            "message": f"Invalid {field_name} value '{field_value}'. Must use standardized values from security_log_fields. Valid options: {', '.join(valid_values[:5])}{'...' if len(valid_values) > 5 else ''}"
        }
    
    return {"valid": True}


def _validate_and_collect_errors(
    params: Dict[str, Any],
    required_fields: List[str],
    standardized_fields: List[Dict[str, Any]]
) -> List[str]:
    """
    Validate all required fields at once and return all errors.
    This allows developers to see all missing/invalid fields in a single error message.
    
    Args:
        params: Dictionary of parameters to validate
        required_fields: List of required field names
        standardized_fields: List of dicts with 'field' and optional 'allow_custom' keys
        
    Returns:
        List of error messages (empty if valid)
    """
    errors = []
    
    # Check required fields
    missing_fields = []
    for field in required_fields:
        value = params.get(field)
        if value is None:
            missing_fields.append(field)
        elif isinstance(value, str) and value.strip() == "":
            missing_fields.append(field)
        # Note: Arrays are valid even if empty (e.g., id_list with no results)
    
    if missing_fields:
        errors.append(f"Required fields missing: {', '.join(missing_fields)}")
    
    # Validate standardized values
    for field_config in standardized_fields:
        field = field_config['field']
        allow_custom = field_config.get('allow_custom', False)
        value = params.get(field)
        if value and isinstance(value, str) and value.strip() != "":
            validation = _validate_standardized_field(field, value, allow_custom)
            if not validation["valid"]:
                errors.append(validation["message"])
    
    return errors


# ==================================
# == Helper Functions
# ==================================

def _create_base_log_event(
    timestamp: str = "",
    event_type: str = "",
    log_category: str = "",
    status: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    service_component_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = "",
    **kwargs
) -> Dict[str, Any]:
    """
    Create a base log event with all required and optional fields.
    Automatically adds caller context (function name, file name).
    
    Environment fields (cloud_env_type, cloud_env_unique_id, etc.) will use
    values from init_security_logging() if not provided here.
    
    Returns:
        Dict containing the complete log event
    """
    # Use current timestamp if not provided
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    
    # Get caller context
    caller_context = _get_caller_context()
    
    # Get environment config set during initialization
    # These values are used as defaults if not provided as arguments
    env_config = _env_config
    
    # Create the base event structure
    # Arguments take precedence over init-time config
    event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "log_category": log_category,
        "status": status,
        "actor_identifier": actor_identifier,
        "actor_type": actor_type,
        "session_id": session_id,
        # Environment fields: args override init-time config
        "cloud_env_type": cloud_env_type or env_config.get('cloud_env_type', ''),
        "service_name": service_name or env_config.get('service_name', ''),
        "cloud_env_unique_id": cloud_env_unique_id or env_config.get('cloud_env_unique_id', ''),
        "cloud_env_name": cloud_env_name or env_config.get('cloud_env_name', ''),
        "service_account_id": service_account_id or env_config.get('service_account_id', ''),
        "source_ip_address": source_ip_address,
        "cloud_service_api_type": cloud_service_api_type,
        **caller_context
    }
    
    # Add optional service_component_name if provided
    if service_component_name:
        event["service_component_name"] = service_component_name
    
    # Add trace context fields
    if trace_id:
        event["trace_id"] = trace_id
    if span_id:
        event["span_id"] = span_id
    if parent_span_id:
        event["parent_span_id"] = parent_span_id
    
    # Add all additional fields from kwargs
    event.update(kwargs)
    
    return event


# ==================================
# == Authentication & Session Functions
# ==================================

def log_user_login(
    # Required base fields
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    # Required event fields
    event_type: str,
    user_agent: str,
    user_role: str,
    status: str,
    auth_protocol: str,
    # Common fields
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    # Optional fields
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    detail: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs User Login attempts (both success and failure).
    
    Args:
        cloud_env_type: Environment type (CloudEnvType.PROD, etc.). Example: "prod"
        cloud_env_unique_id: AWS Account ID. Example: "123456789012"
        cloud_env_name: Human-readable environment name. Example: "production-us-west-2"
        service_account_id: IAM role ARN. Example: "arn:aws:iam::123456789012:role/AuthService"
        service_name: Service generating the log. Example: "auth-service"
        event_type: Must be EventType.LOGIN_ATTEMPT. Example: "login_attempt"
        user_agent: Browser/device info. Example: "Mozilla/5.0 (Windows NT 10.0...)"
        user_role: User's role. Example: UserRole.ADMIN → "role.classification.admin"
        status: Outcome. Example: Status.SUCCESS → "status.general.success"
        auth_protocol: Protocol used. Example: AuthProtocol.OAUTH2_JWT → "auth.protocol.oauth2.jwt"
        actor_identifier: User email or ID. Example: "user@company.com"
        actor_type: Type of actor. Example: ActorType.HUMAN_INTERNAL
        session_id: Session identifier. Example: "sess_abc123"
        detail: Optional context. Example: Detail.USER_INITIATED
    
    Returns:
        Dict with "status" key ("success" or "failure")
        
    Example:
        >>> result = log_user_login(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::123456789012:role/AuthService",
        ...     service_name="auth-service",
        ...     event_type=EventType.LOGIN_ATTEMPT,
        ...     status=Status.SUCCESS,
        ...     user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ...     user_role=UserRole.ADMIN,
        ...     auth_protocol=AuthProtocol.OAUTH2_JWT,
        ...     actor_identifier="john.doe@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_abc123",
        ...     detail=Detail.USER_INITIATED
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'user_agent': user_agent,
            'user_role': user_role,
            'status': status,
            'auth_protocol': auth_protocol
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + ['event_type', 'status', 'user_agent', 'user_role', 'auth_protocol']
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'status'},
            {'field': 'user_role'},
            {'field': 'auth_protocol'},
            {'field': 'actor_type'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        params['actor_type'] = actor_type
        params['detail'] = detail
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for user login:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHN_SESSION,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            user_agent=user_agent,
            user_role=user_role,
            auth_protocol=auth_protocol,
            detail=detail,
            device_id=device_id,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_login: {str(e)}"}


def log_mfa_challenge(
    # Required base fields
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    # Required event fields
    event_type: str,
    user_agent: str,
    user_role: str,
    status: str,
    mfa_type: str,
    # Common fields
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    # Optional fields
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    detail: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs MFA Challenge events.
    
    Args:
        cloud_env_type: Environment type. Example: CloudEnvType.PROD → "prod"
        cloud_env_unique_id: AWS Account ID. Example: "123456789012"
        cloud_env_name: Environment name. Example: "production"
        service_account_id: IAM role ARN. Example: "arn:aws:iam::..."
        service_name: Service name. Example: "auth-service"
        event_type: Must be EventType.MFA_CHALLENGE. Example: "mfa_challenge"
        user_agent: Browser info. Example: "Mozilla/5.0..."
        user_role: User's role. Example: UserRole.ADMIN
        status: Outcome. Example: Status.SUCCESS
        mfa_type: MFA type used. Example: MfaType.OKTA_VERIFY → "okta_verify"
        detail: Optional context. Example: Detail.MFA_INVALID_CODE for failures
    
    Returns:
        Dict with "status" key ("success" or "failure")
        
    Example:
        >>> result = log_mfa_challenge(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::123456789012:role/AuthService",
        ...     service_name="auth-service",
        ...     event_type=EventType.MFA_CHALLENGE,
        ...     status=Status.SUCCESS,
        ...     user_agent="Mozilla/5.0...",
        ...     user_role=UserRole.ADMIN,
        ...     mfa_type=MfaType.OKTA_VERIFY,
        ...     actor_identifier="user@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_abc123"
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'user_agent': user_agent,
            'user_role': user_role,
            'status': status,
            'mfa_type': mfa_type,
            'actor_type': actor_type,
            'detail': detail
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + ['event_type', 'status', 'user_agent', 'user_role', 'mfa_type']
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'status'},
            {'field': 'user_role'},
            {'field': 'mfa_type'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for MFA challenge:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHN_SESSION,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            user_agent=user_agent,
            user_role=user_role,
            detail=detail,
            device_id=device_id,
            mfa_type=mfa_type,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_mfa_challenge: {str(e)}"}


def log_user_logout(
    # Required base fields
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    # Required event fields
    event_type: str,
    user_agent: str,
    user_role: str,
    status: str,
    # Common fields
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    # Optional fields
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    detail: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs User Logout events.
    
    Args:
        cloud_env_type: Environment type. Example: CloudEnvType.PROD
        cloud_env_unique_id: AWS Account ID. Example: "123456789012"
        cloud_env_name: Environment name. Example: "production"
        service_account_id: IAM role ARN
        service_name: Service name
        event_type: Must be EventType.USER_LOGOUT. Example: "user_logout"
        user_agent: Browser info
        user_role: User's role
        status: Outcome. Example: Status.SUCCESS
        detail: Reason for logout. Example: Detail.USER_INITIATED or Detail.SESSION_TIMEOUT
    
    Returns:
        Dict with "status" key ("success" or "failure")
        
    Example:
        >>> result = log_user_logout(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::...",
        ...     service_name="auth-service",
        ...     event_type=EventType.USER_LOGOUT,
        ...     status=Status.SUCCESS,
        ...     user_agent="Mozilla/5.0...",
        ...     user_role=UserRole.ADMIN,
        ...     actor_identifier="user@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_abc123",
        ...     detail=Detail.USER_INITIATED
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'user_agent': user_agent,
            'user_role': user_role,
            'status': status,
            'actor_type': actor_type,
            'detail': detail
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + ['event_type', 'status', 'user_agent', 'user_role']
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'status'},
            {'field': 'user_role'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for user logout:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHN_SESSION,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            user_agent=user_agent,
            user_role=user_role,
            detail=detail,
            device_id=device_id,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_logout: {str(e)}"}


# ==================================
# == Customer Data Actions Functions
# ==================================

def log_record_access(
    # Required base fields
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    # Required event fields
    event_type: str,
    endpoint_path: str,
    data_sensitivity_level: str,
    id_list: List[str],
    detail: str,
    # Common fields
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    # Optional fields
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    fields_accessed: List[str] = None,
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Log record access events (single or multiple records).
    
    This unified function handles both single and multiple record access logging.
    - record_count is automatically calculated from id_list
    - Large id_list arrays are automatically batched to fit SNS message limits
    - Each batch includes event_uuid, part_number, total_parts for correlation
    
    Args:
        cloud_env_type: Environment type. Example: CloudEnvType.PROD
        cloud_env_unique_id: AWS Account ID. Example: "123456789012"
        cloud_env_name: Environment name. Example: "production"
        service_account_id: IAM role ARN
        service_name: Service name
        event_type: Must be EventType.RECORD_ACCESS. Example: "record_access"
        endpoint_path: API endpoint. Example: "/api/v1/customers"
        data_sensitivity_level: Data sensitivity. Example: DataSensitivityLevel.CONFIDENTIAL
        id_list: List of record IDs accessed. Example: ["cust_123", "cust_456"]
        detail: Action type. Example: Detail.VIEW_LIST or Detail.VIEW_RECORD
        fields_accessed: Optional list of fields accessed (for single record)
    
    Returns:
        Dict with "status" key ("success" or "failure")
        
    Example:
        >>> # Viewing a list of customer records
        >>> result = log_record_access(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::...",
        ...     service_name="customer-portal",
        ...     event_type=EventType.RECORD_ACCESS,
        ...     endpoint_path="/api/v1/customers",
        ...     data_sensitivity_level=DataSensitivityLevel.CONFIDENTIAL,
        ...     id_list=["cust_123", "cust_456", "cust_789"],
        ...     detail=Detail.VIEW_LIST,
        ...     actor_identifier="user@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_abc123"
        ... )
        
        >>> # Viewing a single record with specific fields
        >>> result = log_record_access(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::...",
        ...     service_name="customer-portal",
        ...     event_type=EventType.RECORD_ACCESS,
        ...     endpoint_path="/api/v1/customers/cust_123",
        ...     data_sensitivity_level=DataSensitivityLevel.PII_FINANCIAL,
        ...     id_list=["cust_123"],
        ...     detail=Detail.VIEW_RECORD,
        ...     fields_accessed=["ssn", "bank_account"],
        ...     actor_identifier="finance@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_xyz789"
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'endpoint_path': endpoint_path,
            'data_sensitivity_level': data_sensitivity_level,
            'id_list': id_list,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'endpoint_path', 'data_sensitivity_level', 'id_list', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'data_sensitivity_level'},
            {'field': 'detail'}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for record access:\n- " + "\n- ".join(errors)
            }
        
        # Build event - record_count is calculated by the publisher from id_list
        event_kwargs = {
            'timestamp': timestamp,
            'event_type': event_type,
            'log_category': LogCategory.CUSTOMER_DATA_ACTIONS,
            'status': Status.SUCCESS,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id,
            'cloud_env_type': cloud_env_type,
            'service_name': service_name,
            'service_component_name': service_component_name,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'source_ip_address': source_ip_address,
            'cloud_service_api_type': cloud_service_api_type,
            'trace_id': trace_id,
            'span_id': span_id,
            'parent_span_id': parent_span_id,
            'endpoint_path': endpoint_path,
            'data_sensitivity_level': data_sensitivity_level,
            'id_list': id_list,  # Publisher will handle batching
            'detail': detail,
        }
        
        if fields_accessed:
            event_kwargs['fields_accessed'] = fields_accessed
        
        event = _create_base_log_event(**event_kwargs)
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_record_access: {str(e)}"}


# ==================================
# == Authorization & Access Functions
# ==================================

def log_permission_role_change(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_user_identifier: str,
    object_changed: str,
    previous_value: str,
    new_value: str,
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    detail: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Permission/Role/Group Membership Change events.
    
    Args:
        cloud_env_type: Environment type. Example: CloudEnvType.PROD
        cloud_env_unique_id: AWS Account ID
        cloud_env_name: Environment name
        service_account_id: IAM role ARN
        service_name: Service name
        event_type: Must be EventType.PERMISSION_CHANGE
        target_user_identifier: User whose permissions changed
        object_changed: What was changed (e.g., "Role", "Group")
        previous_value: Value before change
        new_value: Value after change
        detail: Optional context
    
    Example:
        >>> result = log_permission_role_change(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::...",
        ...     service_name="admin-service",
        ...     event_type=EventType.PERMISSION_CHANGE,
        ...     target_user_identifier="target.user@sunrun.com",
        ...     object_changed="Role",
        ...     previous_value="viewer",
        ...     new_value="admin",
        ...     actor_identifier="admin@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_admin123",
        ...     detail=Detail.ADMIN_INITIATED
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_user_identifier': target_user_identifier,
            'object_changed': object_changed,
            'previous_value': previous_value,
            'new_value': new_value,
            'detail': detail
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_user_identifier', 'object_changed', 'previous_value', 'new_value'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for permission change:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_user_identifier=target_user_identifier,
            object_changed=object_changed,
            previous_value=previous_value,
            new_value=new_value,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_permission_role_change: {str(e)}"}


def log_user_status_change(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_user_identifier: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Log user status changes (enabled/disabled/deleted/locked/unlocked).
    
    Args:
        event_type: Must be EventType.USER_STATUS_CHANGE
        target_user_identifier: User whose status changed
        detail: Action taken. Example: Detail.USER_DISABLED
    
    Example:
        >>> result = log_user_status_change(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::...",
        ...     service_name="admin-service",
        ...     event_type=EventType.USER_STATUS_CHANGE,
        ...     target_user_identifier="terminated.user@sunrun.com",
        ...     detail=Detail.USER_DISABLED,
        ...     actor_identifier="admin@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_admin123"
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_user_identifier': target_user_identifier,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_user_identifier', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'detail'}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for user status change:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_user_identifier=target_user_identifier,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_status_change: {str(e)}"}


def log_impersonation_event(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_user_identifier: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Log user impersonation start/stop events.
    
    Args:
        event_type: Must be EventType.IMPERSONATION_EVENT
        target_user_identifier: User being impersonated
        detail: Action type. Example: Detail.IMPERSONATION_START or Detail.IMPERSONATION_STOP
    
    Example:
        >>> result = log_impersonation_event(
        ...     cloud_env_type=CloudEnvType.PROD,
        ...     cloud_env_unique_id="123456789012",
        ...     cloud_env_name="production",
        ...     service_account_id="arn:aws:iam::...",
        ...     service_name="support-portal",
        ...     event_type=EventType.IMPERSONATION_EVENT,
        ...     target_user_identifier="customer@example.com",
        ...     detail=Detail.IMPERSONATION_START,
        ...     actor_identifier="support.agent@sunrun.com",
        ...     actor_type=ActorType.HUMAN_INTERNAL,
        ...     session_id="sess_support123"
        ... )
    """
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_user_identifier': target_user_identifier,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_user_identifier', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for impersonation event:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_user_identifier=target_user_identifier,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_impersonation_event: {str(e)}"}


def log_user_invite_event(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_user_email: str,
    assigned_role: str,
    invite_status: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """Log user invitation events."""
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_user_email': target_user_email,
            'assigned_role': assigned_role,
            'invite_status': invite_status,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_user_email', 'assigned_role', 'invite_status', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'invite_status'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for user invite event:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_user_email=target_user_email,
            assigned_role=assigned_role,
            invite_status=invite_status,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_invite_event: {str(e)}"}


# ==================================
# == API Endpoint Access Functions
# ==================================

def log_api_request(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    auth_protocol: str,
    endpoint_path: str,
    http_method: str,
    authorization_status: str,
    endpoint_sensitivity: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    detail: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """Log API endpoint access attempts."""
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'auth_protocol': auth_protocol,
            'endpoint_path': endpoint_path,
            'http_method': http_method,
            'authorization_status': authorization_status,
            'endpoint_sensitivity': endpoint_sensitivity,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id,
            'detail': detail
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'auth_protocol', 'endpoint_path', 'http_method', 'authorization_status', 'endpoint_sensitivity'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'auth_protocol'},
            {'field': 'http_method'},
            {'field': 'endpoint_sensitivity'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for API request:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.API_ENDPOINT_ACCESS,
            status=authorization_status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            auth_protocol=auth_protocol,
            endpoint_path=endpoint_path,
            http_method=http_method,
            authorization_status=authorization_status,
            endpoint_sensitivity=endpoint_sensitivity,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_api_request: {str(e)}"}


# ==================================
# == Key Configuration Changes Functions
# ==================================

def log_mfa_status_change(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_object: str,
    status: str,
    mfa_id: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """Log MFA configuration changes."""
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_object': target_object,
            'status': status,
            'mfa_id': mfa_id,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_object', 'status', 'mfa_id', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'status'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for MFA status change:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_object=target_object,
            mfa_id=mfa_id,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_mfa_status_change: {str(e)}"}


def log_password_change_reset(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_object: str,
    status: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """Log password change/reset events."""
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_object': target_object,
            'status': status,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_object', 'status', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'status'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for password change/reset:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_object=target_object,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_password_change_reset: {str(e)}"}


def log_api_key_lifecycle(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_object: str,
    status: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """Log API key management events."""
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_object': target_object,
            'status': status,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_object', 'status', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'status'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for API key lifecycle:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_object=target_object,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_api_key_lifecycle: {str(e)}"}


def log_auth_mechanism_modification(
    cloud_env_type: str,
    cloud_env_unique_id: str,
    cloud_env_name: str,
    service_account_id: str,
    service_name: str,
    event_type: str,
    target_object: str,
    status: str,
    detail: str,
    actor_identifier: str,
    actor_type: str,
    session_id: str,
    timestamp: str = "",
    service_component_name: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """Log authentication mechanism changes."""
    try:
        params = {
            'cloud_env_type': cloud_env_type,
            'cloud_env_unique_id': cloud_env_unique_id,
            'cloud_env_name': cloud_env_name,
            'service_account_id': service_account_id,
            'service_name': service_name,
            'event_type': event_type,
            'target_object': target_object,
            'status': status,
            'detail': detail,
            'actor_identifier': actor_identifier,
            'actor_type': actor_type,
            'session_id': session_id
        }
        
        required_fields = COMMON_REQUIRED_FIELDS + [
            'event_type', 'actor_identifier', 'actor_type', 'session_id',
            'target_object', 'status', 'detail'
        ]
        
        standardized_fields = [
            {'field': 'event_type'},
            {'field': 'actor_type'},
            {'field': 'status'},
            {'field': 'detail', 'allow_custom': True}
        ]
        
        errors = _validate_and_collect_errors(params, required_fields, standardized_fields)
        if errors:
            return {
                "status": "failure",
                "message": f"Validation errors for auth mechanism modification:\n- " + "\n- ".join(errors)
            }
        
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=status,
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            service_component_name=service_component_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            target_object=target_object,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_auth_mechanism_modification: {str(e)}"}
