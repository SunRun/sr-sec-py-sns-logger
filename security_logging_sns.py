# File: security_logging_sns.py

import os
import sys
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

# Global SNS publisher instance - initialized once per application
_sns_publisher: Optional[SNSPublisher] = None

# Global error handler for fire-and-forget logging
_error_handler = None

def init_security_logging(
    topic_arn: str = None, 
    region_name: str = None,
    failover_topic_arn: str = None,
    failover_region: str = None,
    enable_failover: bool = True,
    test_mode: bool = False
):
    """
    Initialize the security logging module with optional multi-region failover.
    
    Args:
        topic_arn: Primary SNS Topic ARN. If None, uses default or SECURITY_LOGS_TOPIC_ARN env var
        region_name: Primary AWS region. If None, uses us-west-2
        failover_topic_arn: Failover SNS Topic ARN (optional). If None, reads from SECURITY_LOGS_FAILOVER_TOPIC_ARN env var
        failover_region: Failover AWS region. If None, uses us-east-2
        enable_failover: Enable automatic failover (default: True). Set to False to disable failover
        test_mode: If True, logs are printed to console instead of sent to SNS
    
    Example:
        # Basic initialization (no failover)
        init_security_logging(
            topic_arn="arn:aws:sns:us-west-2:123456789012:my-topic"
        )
        
        # With failover enabled
        init_security_logging(
            topic_arn="arn:aws:sns:us-west-2:123456789012:my-topic",
            failover_topic_arn="arn:aws:sns:us-east-2:123456789012:my-failover-topic",
            enable_failover=True
        )
    """
    global _sns_publisher
    
    # Default production ARNs and regions
    DEFAULT_TOPIC_ARN = "arn:aws:sns:us-west-2:000576341507:sr-sec-logging-log-topic-prod"
    DEFAULT_REGION = "us-west-2"
    DEFAULT_FAILOVER_REGION = "us-east-2"
    
    # Primary topic configuration
    if topic_arn is None:
        # First try environment variable, then use default
        topic_arn = os.environ.get("SECURITY_LOGS_TOPIC_ARN")
        if not topic_arn:
            if test_mode:
                topic_arn = "arn:aws:sns:us-east-1:123456789012:test-security-logs"
            else:
                topic_arn = DEFAULT_TOPIC_ARN
    
    if region_name is None:
        # First try environment variable, then use default
        region_name = os.environ.get("AWS_REGION")
        if not region_name:
            region_name = DEFAULT_REGION
    
    # Failover topic configuration
    if failover_topic_arn is None and enable_failover:
        # Try environment variable for failover topic
        failover_topic_arn = os.environ.get("SECURITY_LOGS_FAILOVER_TOPIC_ARN")
    
    if failover_region is None:
        failover_region = os.environ.get("SECURITY_LOGS_FAILOVER_REGION", DEFAULT_FAILOVER_REGION)
    
    _sns_publisher = SNSPublisher(
        topic_arn=topic_arn,
        region_name=region_name,
        failover_topic_arn=failover_topic_arn,
        failover_region=failover_region,
        enable_failover=enable_failover,
        test_mode=test_mode
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
        metrics = get_failover_metrics()
        print(f"Failover used: {metrics['failover_success']} times")
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
        def my_error_handler(error_msg, event_type):
            print(f"Security logging failed for {event_type}: {error_msg}")
            cloudwatch.put_metric('SecurityLoggingFailure', 1, {'EventType': event_type})
        
        set_security_logging_error_handler(my_error_handler)
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
        # Instead of awaiting (which blocks):
        # result = log_user_login(...)
        
        # Use fire-and-forget (non-blocking):
        with ThreadPoolExecutor() as executor:
            future = executor.submit(log_user_login, 
                event_type=EventType.LOGIN_ATTEMPT,
                status=Status.SUCCESS,
                actor_identifier="user@company.com",
                # ... other parameters
            )
            fire_and_forget(future, EventType.LOGIN_ATTEMPT)
        
        # Application continues immediately - not blocked by SNS!
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
            EndpointSensitivity.PUBLIC, EndpointSensitivity.INTERNAL, EndpointSensitivity.CONFIDENTIAL,
            EndpointSensitivity.PII_BASIC, EndpointSensitivity.PII_FINANCIAL, EndpointSensitivity.PII_HEALTH,
            EndpointSensitivity.CREDENTIAL_MANAGEMENT, EndpointSensitivity.SYSTEM_ADMIN, EndpointSensitivity.AUTHENTICATION
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
            # MFA Actions (for mfa_status_change events)
            Detail.MFA_DISABLED, Detail.MFA_ENABLED, Detail.NEW_MFA_DEVICE,
            # MFA Challenge failure reasons (for mfa_challenge events)
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
    if not field_value or field_value.strip() == "":
        return {"valid": True}  # Empty values are handled by required field validation
    
    valid_values = _get_valid_values_for_field(field_name)
    if not valid_values:
        return {"valid": True}  # Field doesn't have standardized values
    
    # Special handling for detail field - allow custom text for success contexts
    if field_name == "detail" and allow_custom_for_detail:
        # If it's not a standardized detail value, assume it's custom success context
        if field_value not in valid_values:
            return {"valid": True}
    
    if field_value not in valid_values:
        return {
            "valid": False,
            "message": f"Invalid {field_name} value '{field_value}'. Must use standardized values from security_log_fields. Valid options: {', '.join(valid_values[:5])}{'...' if len(valid_values) > 5 else ''}"
        }
    
    return {"valid": True}

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
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = "",
    **kwargs  # Additional event-specific fields
) -> Dict[str, Any]:
    """
    Create a base log event with all required and optional fields.
    
    Returns:
        Dict containing the complete log event or error status
    """
    
    # Use current timestamp if not provided
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    
    # Create the base event structure
    event = {
        # Base log fields
        "timestamp": timestamp,
        "event_type": event_type,
        "log_category": log_category,
        "status": status,
        "actor_identifier": actor_identifier,
        "actor_type": actor_type,
        "session_id": session_id,
        "cloud_env_type": cloud_env_type,
        "service_name": service_name,
        "cloud_env_unique_id": cloud_env_unique_id,
        "cloud_env_name": cloud_env_name,
        "service_account_id": service_account_id,
        "source_ip_address": source_ip_address,
        "cloud_service_api_type": cloud_service_api_type,
    }
    
    # Add trace context fields (W3C Trace Context support)
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
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # Must be EventType.LOGIN_ATTEMPT
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    user_agent: str = "",
    user_role: str = "",
    status: str = "",  # Status.SUCCESS or Status.FAILURE
    auth_protocol: str = "",  # AuthProtocol constant (e.g., AuthProtocol.OAUTH2_JWT)
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    detail: str = "",  # Context like "1st time login", "invalid_credentials",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs User Login attempts (both success and failure).
    
    Required fields:
    - event_type: EventType.LOGIN_ATTEMPT
    - status: Status.SUCCESS or Status.FAILURE
    - user_agent: Browser/device info
    - user_role: Role of the user at the time of login
    - auth_protocol: Authentication protocol used (AuthProtocol.OAUTH2_JWT, AuthProtocol.SAML, etc.)
    
    Optional fields:
    - detail: Context for success/failure (e.g., "1st time login", "invalid_credentials")
    - device_id: Unique device identifier
    """
    try:
        # Validate required fields including base and event-specific
        required_fields = {
            "event_type": event_type,
            "status": status,
            "user_agent": user_agent,
            "user_role": user_role,
            "auth_protocol": auth_protocol,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for user login: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
            _validate_standardized_field("user_role", user_role),
            _validate_standardized_field("auth_protocol", auth_protocol),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
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
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "mfa_challenge"
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    user_agent: str = "",
    user_role: str = "",
    status: str = "",  # "status.general.success" or "status.general.failure"
    mfa_type: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    detail: str = "",  # Context for success/failure,
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs MFA Challenge events.
    
    Required fields:
    - event_type: "mfa_challenge"
    - status: "status.general.success" or "status.general.failure"
    - user_agent: Browser/device info
    - user_role: Role of the user attempting the challenge
    - mfa_type: The type of MFA used (e.g., "sms", "okta verify")
    
    Optional fields:
    - detail: Context for success/failure
    - device_id: Unique device identifier
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "status": status,
            "user_agent": user_agent,
            "user_role": user_role,
            "mfa_type": mfa_type,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for MFA challenge: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
            _validate_standardized_field("user_role", user_role),
            _validate_standardized_field("mfa_type", mfa_type),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
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
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "user_logout"
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    user_agent: str = "",
    user_role: str = "",
    status: str = "",  # "status.general.success" or "status.general.failure"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    detail: str = "",  # e.g., "timeout", "user_initiated", "concurrent_session", "admin_initiated",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs User Logout events.
    
    Required fields:
    - event_type: "user_logout"
    - status: "status.general.success" or "status.general.failure"
    - user_agent: Browser/device info
    - user_role: Role of the user who logged out
    
    Optional fields:
    - detail: Why the logout occurred (e.g., "timeout", "user_initiated", "concurrent_session")
    - device_id: Unique device identifier
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "status": status,
            "user_agent": user_agent,
            "user_role": user_role,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for user logout: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
            _validate_standardized_field("user_role", user_role),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            user_agent=user_agent,
            user_role=user_role,
            detail=detail,
            device_id=device_id,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_logout: {str(e)}"}

# ==================================
# == Authorization & Access Functions
# ==================================

def log_permission_role_change(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "permission_change"
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_user_identifier: str = "",
    object_changed: str = "",  # e.g., "Role", "Group"
    previous_value: str = "",
    new_value: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    detail: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Permission/Role/Group Membership Change events.
    
    Required fields:
    - event_type: "permission_change"
    - target_user_identifier: The user whose permissions were modified
    - object_changed: The entity that was changed (e.g., "Role", "Group")
    - previous_value: The value before the change
    - new_value: The value after the change
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_user_identifier": target_user_identifier,
            "object_changed": object_changed,
            "previous_value": previous_value,
            "new_value": new_value,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for permission change: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,  # Permission changes are typically successful when logged
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
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
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "user_status_change"
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_user_identifier: str = "",
    detail: str = "",  # e.g., "detail.action.user_disabled", "detail.action.user_deleted"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs User Status Events (Disabled/Blocked, Enabled/Unblocked, Deleted).
    
    Required fields:
    - event_type: "user_status_change"
    - target_user_identifier: The user whose status was changed
    - detail: The specific action (e.g., "detail.action.user_disabled", "detail.action.user_enabled")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_user_identifier": target_user_identifier,
            "detail": detail,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for user status change: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("detail", detail),
        ]
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,  # Status changes are typically successful when logged
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            target_user_identifier=target_user_identifier,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_status_change: {str(e)}"}

def log_impersonation_event(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "impersonation_event"
    actor_identifier: str = "",  # The admin/support user
    actor_type: str = "",
    session_id: str = "",  # The admin's session
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_user_identifier: str = "",  # The user being impersonated
    detail: str = "",  # "detail.action.impersonation_start" or "detail.action.impersonation_stop"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Impersonation Events (Start/Stop).
    
    Required fields:
    - event_type: "impersonation_event"
    - actor_identifier: The admin/support user performing the impersonation
    - session_id: The admin's session
    - target_user_identifier: The user being impersonated
    - detail: "detail.action.impersonation_start" or "detail.action.impersonation_stop"
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_user_identifier": target_user_identifier,
            "detail": detail,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for impersonation event: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
        ]
        
        # Validate detail field (required for this function)
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,  # Impersonation events are typically successful when logged
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            target_user_identifier=target_user_identifier,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_impersonation_event: {str(e)}"}

def log_user_invite_event(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "user_invite_event"
    actor_identifier: str = "",  # Who sent the invite
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_user_email: str = "",  # Email of the invitee
    assigned_role: str = "",
    invite_status: str = "",  # e.g., "sent", "accepted", "revoked"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    detail: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs User Invite events (Sent/Accepted/Revoked/Expired).
    
    Required fields:
    - event_type: "user_invite_event"
    - actor_identifier: Who sent the invite
    - target_user_email: Email address of the invited user
    - assigned_role: The role assigned in the invitation
    - invite_status: Current status of the invite (e.g., "sent", "accepted", "revoked")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_user_email": target_user_email,
            "assigned_role": assigned_role,
            "invite_status": invite_status,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for user invite event: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("invite_status", invite_status),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHZ_ACCESS,
            status=Status.SUCCESS,  # Invite events are typically successful when logged
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
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
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "api_request_processed"
    actor_identifier: str = "",  # Service account or client ID or normalized user ID
    actor_type: str = "",
    session_id: str = "",  # Important to correlate user session if using user flow
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    auth_protocol: str = "",  # e.g., "api_key", "oauth2_jwt", "oauth2_client_secret"
    endpoint_path: str = "",  # The specific endpoint URI accessed
    http_method: str = "",  # GET, POST, PUT, DELETE
    authorization_status: str = "",  # Success/Failure
    endpoint_sensitivity: str = "",  # e.g., "Confidential-PII", "Public", "Login"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    detail: str = "",  # e.g., "invalid_token", "expired_token", "ip_not_on_allowlist",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs API Request Processed events.
    
    Required fields:
    - event_type: "api_request_processed"
    - auth_protocol: The authentication protocol used
    - endpoint_path: The path of the API endpoint accessed
    - http_method: The HTTP method used
    - authorization_status: Success/Failure status
    - endpoint_sensitivity: The sensitivity level of the endpoint
    
    Optional fields:
    - detail: Context for failures (e.g., "invalid_token", "expired_token")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "auth_protocol": auth_protocol,
            "endpoint_path": endpoint_path,
            "http_method": http_method,
            "authorization_status": authorization_status,
            "endpoint_sensitivity": endpoint_sensitivity,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for API request: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("auth_protocol", auth_protocol),
            _validate_standardized_field("http_method", http_method),
            _validate_standardized_field("endpoint_sensitivity", endpoint_sensitivity),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.API_ENDPOINT_ACCESS,
            status=authorization_status,  # Use authorization_status as the main status
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
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
# == Customer Data Actions Functions
# ==================================

def log_multi_record_access(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "multi_record_access"
    actor_identifier: str = "",  # e.g., api_client_id, normalized_user_id
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    endpoint_path: str = "",  # e.g., "/api/v1/customers"
    data_sensitivity_level: str = "",  # e.g., "Confidential-PII"
    record_count: int = 0,
    customer_id_list: List[str] = None,
    detail: str = "",  # e.g., "detail.action.view_list", "detail.action.export_report"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Multi-Record Customer Data Actions (View/Modify List, Export/Download Report).
    
    Required fields:
    - event_type: "multi_record_access"
    - endpoint_path: The API endpoint used for the action
    - data_sensitivity_level: The sensitivity of the data being accessed
    - record_count: The number of records affected/accessed
    - customer_id_list: A list of the unique customer IDs accessed
    - detail: The specific action (e.g., "detail.action.view_list", "detail.action.export_report")
    """
    try:
        # Handle default for customer_id_list
        if customer_id_list is None:
            customer_id_list = []
        
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "endpoint_path": endpoint_path,
            "data_sensitivity_level": data_sensitivity_level,
            "detail": detail,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        # Check numeric fields
        if record_count <= 0:
            missing_fields.append("record_count")
        
        if not customer_id_list:
            missing_fields.append("customer_id_list")
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for multi-record access: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("detail", detail),
        ]
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.CUSTOMER_DATA_ACTIONS,
            status=Status.SUCCESS,  # Multi-record access events are typically successful when logged
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            endpoint_path=endpoint_path,
            data_sensitivity_level=data_sensitivity_level,
            record_count=record_count,
            customer_id_list=customer_id_list,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_multi_record_access: {str(e)}"}

def log_single_record_access(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "single_record_access"
    actor_identifier: str = "",  # e.g., api_client_id, normalized_user_id
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    customer_id: str = "",  # Whose data was accessed
    fields_accessed: List[str] = None,  # e.g., ["email", "phone"]
    detail: str = "",  # e.g., "detail.action.view_record", "detail.action.edit_record"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Single Record Customer Data Actions (View/Modify Personal Data).
    
    Required fields:
    - event_type: "single_record_access"
    - customer_id: The unique ID of the customer whose record was accessed
    - fields_accessed: A list of the specific fields that were viewed or modified
    - detail: The specific action (e.g., "detail.action.view_record", "detail.action.edit_record")
    """
    try:
        # Handle default for fields_accessed
        if fields_accessed is None:
            fields_accessed = []
        
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "customer_id": customer_id,
            "detail": detail,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if not fields_accessed:
            missing_fields.append("fields_accessed")
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for single record access: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
        ]
        
        # Validate detail field (required for this function)
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.CUSTOMER_DATA_ACTIONS,
            status=Status.SUCCESS,  # Single record access events are typically successful when logged
            actor_identifier=actor_identifier,
            actor_type=actor_type,
            session_id=session_id,
            cloud_env_type=cloud_env_type,
            service_name=service_name,
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            customer_id=customer_id,
            fields_accessed=fields_accessed,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_single_record_access: {str(e)}"}

# ==================================
# == Key Configuration Changes Functions
# ==================================

def log_mfa_status_change(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "mfa_status_change"
    actor_identifier: str = "",  # Who made the change
    actor_type: str = "",
    session_id: str = "",  # The admin's session
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",  # e.g., User ID for MFA
    status: str = "",  # Success/Failure
    mfa_id: str = "",  # Associated unique ID of MFA option that was impacted
    detail: str = "",  # e.g., "detail.action.mfa_disabled", "detail.action.mfa_enabled", "detail.action.new_mfa_device"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs MFA Status Change events.
    
    Required fields:
    - event_type: "mfa_status_change"
    - target_object: The User ID or object whose MFA status was changed
    - status: Success/Failure status
    - mfa_id: The unique ID of the MFA device that was impacted
    - detail: The specific action (e.g., "detail.action.mfa_disabled", "detail.action.mfa_enabled", "detail.action.new_mfa_device")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_object": target_object,
            "status": status,
            "mfa_id": mfa_id,
            "detail": detail,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for MFA status change: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
        ]
        
        # Validate detail field (required for this function)
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            target_object=target_object,
            mfa_id=mfa_id,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_mfa_status_change: {str(e)}"}

def log_password_change_reset(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "password_change_reset"
    actor_identifier: str = "",  # Who made the change
    actor_type: str = "",
    session_id: str = "",  # The admin's session
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",  # e.g., User ID
    status: str = "",  # Success/Failure
    detail: str = "",  # e.g., "detail.action.password_change", "detail.action.password_reset"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Password Change/Reset events.
    
    Required fields:
    - event_type: "password_change_reset"
    - target_object: The User ID whose password was changed or reset
    - status: Success/Failure status
    - detail: The specific action (e.g., "detail.action.password_change", "detail.action.password_reset")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_object": target_object,
            "status": status,
            "detail": detail,
        }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for password change/reset: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
        ]
        
        # Validate detail field (required for this function)
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            target_object=target_object,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_password_change_reset: {str(e)}"}

def log_api_key_lifecycle(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "api_key_lifecycle"
    actor_identifier: str = "",  # Who made the change
    actor_type: str = "",
    session_id: str = "",  # The admin's session
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",  # e.g., API Client ID
    status: str = "",  # Success/Failure
    detail: str = "",  # e.g., "detail.action.api_key_created", "detail.action.api_key_revoked", "detail.action.api_key_permissions_modified"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs API Key Lifecycle events (Created, Revoked, Permissions Modified).
    
    Required fields:
    - event_type: "api_key_lifecycle"
    - target_object: The API Client ID or key that was affected
    - status: Success/Failure status
    - detail: The specific action (e.g., "detail.action.api_key_created", "detail.action.api_key_revoked")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_object": target_object,
            "status": status,
            }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for API key lifecycle: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            target_object=target_object,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_api_key_lifecycle: {str(e)}"}

def log_auth_mechanism_modification(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    event_type: str = "",  # "auth_mechanism_modification"
    actor_identifier: str = "",  # Who made the change
    actor_type: str = "",
    session_id: str = "",  # The admin's session
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",  # e.g., sso_assertion_url, sso_certificate, local_authentication
    status: str = "",  # Success/Failure
    detail: str = "",  # e.g., "detail.action.new_sso_provider", "detail.action.enable_local_authn", "detail.action.disable_sso"
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # W3C Trace Context fields (optional)
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = ""
) -> Dict[str, str]:
    """
    Logs Authentication Mechanism Modification events (disable SSO, allow 2nd authN in parallel).
    
    Required fields:
    - event_type: "auth_mechanism_modification"
    - target_object: The configuration object that was changed
    - status: Success/Failure status
    - detail: The specific action (e.g., "detail.action.new_sso_provider", "detail.action.enable_local_authn")
    """
    try:
        # Validate required fields
        required_fields = {
            "event_type": event_type,
            "target_object": target_object,
            "status": status,
            }
        
        missing_fields = [field for field, value in required_fields.items() 
                         if not value or value.strip() == ""]
        
        if missing_fields:
            return {
                "status": "failure", 
                "message": f"Required fields missing for auth mechanism modification: {', '.join(missing_fields)}"
            }
        
        # Validate standardized values
        standardized_validations = [
            _validate_standardized_field("event_type", event_type),
            _validate_standardized_field("status", status),
        ]
        
        # Validate detail field only if provided
        if detail and detail.strip():
            standardized_validations.append(
                _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            )
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            # Event-specific fields
            target_object=target_object,
            detail=detail,
        )
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_auth_mechanism_modification: {str(e)}"}
