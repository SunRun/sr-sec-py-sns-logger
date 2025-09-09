# File: security_logging_sns.py

import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from security_log_fields import (
    Status, ActorType, LogCategory, EventType, AuthProtocol, Detail, MfaType,
    HttpMethod, CloudEnvType, CloudServiceApiType, DataSensitivityLevel,
    EndpointSensitivity, InviteStatus, UserRole
)
from sns_publisher import SNSPublisher

# Global SNS publisher instance - initialized once per application
_sns_publisher: Optional[SNSPublisher] = None

def init_security_logging(topic_arn: str = None, region_name: str = None, test_mode: bool = False):
    """
    Initialize the security logging module.
    
    Args:
        topic_arn: SNS Topic ARN. If None, reads from SECURITY_LOGS_TOPIC_ARN env var
        region_name: AWS region. If None, reads from AWS_REGION env var or uses AWS default
        test_mode: If True, logs are printed to console instead of sent to SNS
    """
    global _sns_publisher
    
    if topic_arn is None:
        topic_arn = os.environ.get("SECURITY_LOGS_TOPIC_ARN")
        if not topic_arn:
            if test_mode:
                topic_arn = "arn:aws:sns:us-east-1:123456789012:test-security-logs"
            else:
                raise ValueError("topic_arn must be provided or SECURITY_LOGS_TOPIC_ARN environment variable must be set")
    
    if region_name is None:
        region_name = os.environ.get("AWS_REGION")
    
    _sns_publisher = SNSPublisher(topic_arn=topic_arn, region_name=region_name, test_mode=test_mode)

def _get_publisher() -> SNSPublisher:
    """Get the global SNS publisher instance."""
    if _sns_publisher is None:
        raise RuntimeError("Security logging not initialized. Call init_security_logging() first.")
    return _sns_publisher

# ==================================
# == Standardized Values Validation
# ==================================

def _get_valid_values_for_field(field_name: str) -> List[str]:
    """Get list of valid standardized values for a given field."""
    valid_values = {
        "event_type": [
            # Authentication & Session
            EventType.LOGIN_SUCCESS, EventType.LOGIN_FAILURE,
            EventType.LOGOUT_USER_INITIATED, EventType.LOGOUT_SESSION_TIMEOUT, EventType.LOGOUT_ADMIN_INITIATED,
            EventType.MFA_CHALLENGE_SUCCESS, EventType.MFA_CHALLENGE_FAILURE,
            EventType.PASSWORD_CHANGE, EventType.PASSWORD_RESET,
            EventType.MFA_STATUS_ENABLED, EventType.MFA_STATUS_DISABLED, EventType.MFA_DEVICE_ADDED, EventType.MFA_DEVICE_REMOVED,
            EventType.SSO_CONFIG_CREATED, EventType.SSO_CONFIG_MODIFIED, EventType.SSO_CONFIG_DELETED,
            EventType.LOCAL_AUTH_CONFIG_ENABLED, EventType.LOCAL_AUTH_CONFIG_DISABLED,
            # Authorization & Access
            EventType.PERMISSION_GRANT, EventType.PERMISSION_REVOKE,
            EventType.ROLE_ASSIGN, EventType.ROLE_UNASSIGN,
            EventType.GROUP_MEMBERSHIP_ADD, EventType.GROUP_MEMBERSHIP_REMOVE,
            EventType.USER_STATUS_ENABLED, EventType.USER_STATUS_DISABLED, EventType.USER_STATUS_DELETED,
            EventType.USER_STATUS_LOCKED, EventType.USER_STATUS_UNLOCKED,
            EventType.IMPERSONATION_START, EventType.IMPERSONATION_STOP,
            EventType.INVITE_SENT, EventType.INVITE_ACCEPTED, EventType.INVITE_REVOKED, EventType.INVITE_EXPIRED,
            # Customer Data Actions
            EventType.CUSTOMER_RECORD_VIEW, EventType.CUSTOMER_RECORD_MODIFY,
            EventType.CUSTOMER_LIST_VIEW, EventType.CUSTOMER_LIST_MODIFY,
            EventType.REPORT_EXPORT, EventType.REPORT_DOWNLOAD,
            # API Endpoint Access
            EventType.API_REQUEST_SUCCESS, EventType.API_REQUEST_FAILURE,
            # Key Configuration Changes
            EventType.API_KEY_CREATED, EventType.API_KEY_REVOKED, EventType.API_KEY_PERMISSIONS_MODIFIED,
        ],
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
            AuthProtocol.API_KEY, AuthProtocol.OAUTH2_JWT, AuthProtocol.OAUTH2_CLIENT_CREDENTIALS,
            AuthProtocol.OAUTH2_AUTHORIZATION_CODE, AuthProtocol.OAUTH2_IMPLICIT, AuthProtocol.OAUTH2_PASSWORD_GRANT,
            AuthProtocol.SAML, AuthProtocol.OIDC, AuthProtocol.SESSION_COOKIE, AuthProtocol.M2M_TOKEN, AuthProtocol.NONE
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
            Detail.INVALID_REQUEST, Detail.NOT_APPLICABLE
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
# == Base Log Validation
# ==================================

def _validate_base_log_fields(
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
) -> Dict[str, Any]:
    """
    Validate required base log fields and standardized values.
    
    Returns:
        Dict with "valid" boolean and "missing_fields"/"message" if validation fails
    """
    required_fields = {
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
    }
    
    missing_fields = [field for field, value in required_fields.items() if not value or value.strip() == ""]
    
    if missing_fields:
        return {
            "valid": False,
            "missing_fields": missing_fields,
            "message": f"Required base_log fields missing: {', '.join(missing_fields)}"
        }
    
    # Validate standardized field values
    standardized_fields_to_check = {
        "event_type": event_type,
        "log_category": log_category,
        "status": status,
        "actor_type": actor_type,
        "cloud_env_type": cloud_env_type,
    }
    
    for field_name, field_value in standardized_fields_to_check.items():
        validation = _validate_standardized_field(field_name, field_value)
        if not validation["valid"]:
            return {
                "valid": False,
                "message": validation["message"]
            }
    
    return {"valid": True}

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
    **log_specifics
) -> Dict[str, Any]:
    """
    Create a complete log event with base fields and event-specific fields.
    
    Returns:
        Complete log event dictionary or error response
    """
    # If timestamp is empty, generate it
    if not timestamp or timestamp.strip() == "":
        timestamp = datetime.now(timezone.utc).isoformat()
    
    # Validate required base fields
    validation = _validate_base_log_fields(
        timestamp=timestamp,
        event_type=event_type,
        log_category=log_category,
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
    )
    
    if not validation["valid"]:
        return {"status": "failure", "message": validation["message"]}
    
    # Build the complete event
    base_log = {
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
    }
    
    # Add optional base log fields (always include, even if empty)
    base_log["source_ip_address"] = source_ip_address if source_ip_address else ""
    base_log["cloud_service_api_type"] = cloud_service_api_type if cloud_service_api_type else ""
    
    # Add event-specific fields (always include, even if empty)
    for key, value in log_specifics.items():
        if value is not None:
            base_log[key] = str(value) if value else ""
        else:
            base_log[key] = ""
    
    return base_log

# ==================================
# == Authentication & Session Functions
# ==================================

def log_user_login(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
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
    detail: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    # Determine success/failure
    login_successful: bool = True
) -> Dict[str, str]:
    """
    Logs User Login Success and Failure events.
    
    Required log_specifics fields:
    - user_agent: Browser/device info
    - user_role: Role of the user at the time of login
    
    Optional log_specifics fields:
    - detail: Context for success/failure (e.g., "1st time login", "invalid_credentials")
    - device_id: Unique device identifier
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "user_agent": user_agent,
            "user_role": user_role,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for user login: {', '.join(missing_specific)}"
            }
        
        # Validate standardized values for event-specific fields
        standardized_validations = [
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
        
        # Determine event type and status based on success flag
        event_type = EventType.LOGIN_SUCCESS if login_successful else EventType.LOGIN_FAILURE
        status = Status.SUCCESS if login_successful else Status.FAILURE
        
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
            # Event-specific fields
            user_agent=user_agent,
            user_role=user_role,
            detail=detail,
            device_id=device_id,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_login: {str(e)}"}

def log_mfa_challenge(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
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
    detail: str = "",
    mfa_type: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    # Determine success/failure
    challenge_successful: bool = True
) -> Dict[str, str]:
    """
    Logs MFA Challenge events.
    
    Required log_specifics fields:
    - user_agent: Browser/device info
    - user_role: Role of the user attempting the challenge
    - detail: Why the challenge failed or context for success
    - mfa_type: The type of MFA used (e.g., "sms", "okta verify")
    
    Optional log_specifics fields:
    - device_id: Unique device identifier
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "user_agent": user_agent,
            "user_role": user_role,
            "mfa_type": mfa_type,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for MFA challenge: {', '.join(missing_specific)}"
            }
        
        # Validate standardized values for event-specific fields
        standardized_fields = ["user_role", "mfa_type"]
        for field_name in standardized_fields:
            field_value = locals()[field_name]
            if field_value:  # Only validate if value is provided
                validation_result = _validate_standardized_field(field_name, field_value)
                if not validation_result["valid"]:
                    return {
                        "status": "failure", 
                        "message": f"Invalid {field_name} value. {validation_result['message']}"
                    }
        
        # Validate detail field if provided (conditional validation since it's optional)
        if detail:
            detail_validation = _validate_standardized_field("detail", detail, allow_custom_for_detail=True)
            if not detail_validation["valid"]:
                return {
                    "status": "failure", 
                    "message": f"Invalid detail value. {detail_validation['message']}"
                }
        
        # Determine event type and status based on success flag
        event_type = EventType.MFA_CHALLENGE_SUCCESS if challenge_successful else EventType.MFA_CHALLENGE_FAILURE
        status = Status.SUCCESS if challenge_successful else Status.FAILURE
        
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
            # Event-specific fields
            user_agent=user_agent,
            user_role=user_role,
            detail=detail,
            mfa_type=mfa_type,
            device_id=device_id,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_mfa_challenge: {str(e)}"}

def log_user_logout(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
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
    detail: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    device_id: str = "",
    # Logout type
    logout_trigger: str = "user_initiated"  # "user_initiated", "session_timeout", "admin_initiated"
) -> Dict[str, str]:
    """
    Logs User Logout events.
    
    Required log_specifics fields:
    - user_agent: Browser/device info
    - user_role: Role of the user who logged out
    - detail: Why the logout occurred (e.g., "detail.trigger.user_initiated", "detail.trigger.session_timeout")
    
    Optional log_specifics fields:
    - device_id: Unique device identifier
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "user_agent": user_agent,
            "user_role": user_role,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for user logout: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on logout trigger
        event_type_map = {
            "user_initiated": EventType.LOGOUT_USER_INITIATED,
            "session_timeout": EventType.LOGOUT_SESSION_TIMEOUT,
            "admin_initiated": EventType.LOGOUT_ADMIN_INITIATED,
        }
        event_type = event_type_map.get(logout_trigger, EventType.LOGOUT_USER_INITIATED)
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.AUTHN_SESSION,
            status=Status.SUCCESS,  # Logout is typically successful
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
            # Event-specific fields
            user_agent=user_agent,
            user_role=user_role,
            detail=detail,
            device_id=device_id,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_logout: {str(e)}"}

# ==================================
# == Authorization & Access Functions
# ==================================

def log_permission_change(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
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
    object_changed: str = "",
    previous_value: str = "",
    new_value: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Detail for the permission change
    detail: str = ""
) -> Dict[str, str]:
    """
    Logs permission/role/group membership change events.
    
    Required log_specifics fields:
    - target_user_identifier: The user whose permissions were modified
    - object_changed: The entity that was changed (e.g., "Role", "Group")
    - previous_value: The value before the change
    - new_value: The value after the change
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_user_identifier": target_user_identifier,
            "object_changed": object_changed,
            "previous_value": previous_value,
            "new_value": new_value,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for permission change: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on object type - now using permission_name to determine the action
        if "permission" in object_changed.lower():
            # For permissions, assume grant if previous_value is empty/lower, revoke if new_value is empty/lower
            if previous_value and not new_value:
                event_type = EventType.PERMISSION_REVOKE
            else:
                event_type = EventType.PERMISSION_GRANT
        elif "role" in object_changed.lower():
            # For roles, assume assign if new_value exists, unassign if new_value is empty
            if new_value and new_value.strip():
                event_type = EventType.ROLE_ASSIGN
            else:
                event_type = EventType.ROLE_UNASSIGN
        elif "group" in object_changed.lower():
            # For groups, assume add if new_value exists, remove if new_value is empty
            if new_value and new_value.strip():
                event_type = EventType.GROUP_MEMBERSHIP_ADD
            else:
                event_type = EventType.GROUP_MEMBERSHIP_REMOVE
        else:
            # Default to permission grant
            event_type = EventType.PERMISSION_GRANT
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            # Event-specific fields
            target_user_identifier=target_user_identifier,
            object_changed=object_changed,
            previous_value=previous_value,
            new_value=new_value,
            detail=detail,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_permission_change: {str(e)}"}

def log_user_status_change(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
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
    detail: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Status change type
    status_change: str = "enabled"  # "enabled", "disabled", "deleted", "locked", "unlocked"
) -> Dict[str, str]:
    """
    Logs user status change events.
    
    Required log_specifics fields:
    - target_user_identifier: The user whose status was changed
    - detail: The detail for the status change (e.g., "detail.trigger.admin_initiated")
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_user_identifier": target_user_identifier,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for user status change: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on status change
        event_type_map = {
            "enabled": EventType.USER_STATUS_ENABLED,
            "disabled": EventType.USER_STATUS_DISABLED,
            "deleted": EventType.USER_STATUS_DELETED,
            "locked": EventType.USER_STATUS_LOCKED,
            "unlocked": EventType.USER_STATUS_UNLOCKED,
        }
        event_type = event_type_map.get(status_change, EventType.USER_STATUS_ENABLED)
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            # Event-specific fields
            target_user_identifier=target_user_identifier,
            detail=detail,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_status_change: {str(e)}"}

def log_impersonation_event(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
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
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Impersonation action
    impersonation_action: str = "start"  # "start", "stop"
) -> Dict[str, str]:
    """
    Logs impersonation start/stop events.
    
    Required log_specifics fields:
    - target_user_identifier: The user who is being impersonated
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_user_identifier": target_user_identifier,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for impersonation event: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on action
        event_type = EventType.IMPERSONATION_START if impersonation_action == "start" else EventType.IMPERSONATION_STOP
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            # Event-specific fields
            target_user_identifier=target_user_identifier,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_impersonation_event: {str(e)}"}

def log_user_invite_event(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_user_email: str = "",
    assigned_role: str = "",
    invite_status: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
) -> Dict[str, str]:
    """
    Logs user invite events (sent, accepted, revoked, expired).
    
    Required log_specifics fields:
    - target_user_email: The email address of the invited user
    - assigned_role: The role assigned in the invitation
    - invite_status: Current status of the invite (e.g., "sent", "accepted")
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_user_email": target_user_email,
            "assigned_role": assigned_role,
            "invite_status": invite_status,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for user invite event: {', '.join(missing_specific)}"
            }
        
        # Validate standardized values for event-specific fields
        standardized_validations = [
            _validate_standardized_field("invite_status", invite_status),
        ]
        
        for validation in standardized_validations:
            if not validation["valid"]:
                return {"status": "failure", "message": validation["message"]}
        
        # Determine event type based on invite status
        event_type_map = {
            "sent": EventType.INVITE_SENT,
            "accepted": EventType.INVITE_ACCEPTED,
            "revoked": EventType.INVITE_REVOKED,
            "expired": EventType.INVITE_EXPIRED,
        }
        event_type = event_type_map.get(invite_status, EventType.INVITE_SENT)
        
        # Create the log event
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
            cloud_env_unique_id=cloud_env_unique_id,
            cloud_env_name=cloud_env_name,
            service_account_id=service_account_id,
            source_ip_address=source_ip_address,
            cloud_service_api_type=cloud_service_api_type,
            # Event-specific fields
            target_user_email=target_user_email,
            assigned_role=assigned_role,
            invite_status=invite_status,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_invite_event: {str(e)}"}

# ==================================
# == API Endpoint Access Functions
# ==================================

def log_api_request_processed(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    auth_protocol: str = "",
    endpoint_path: str = "",
    http_method: str = "",
    endpoint_sensitivity: str = "",
    detail: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Request success
    request_successful: bool = True
) -> Dict[str, str]:
    """
    Logs API request processed events.
    
    Required log_specifics fields:
    - auth_protocol: The authentication protocol used (e.g., "OAuth", "API Key")
    - endpoint_path: The path of the API endpoint accessed
    - http_method: The HTTP method used (e.g., "GET", "POST")
    - endpoint_sensitivity: The sensitivity level of the endpoint
    - detail: The detail for the API request failure (if applicable)
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "auth_protocol": auth_protocol,
            "endpoint_path": endpoint_path,
            "http_method": http_method,
            "endpoint_sensitivity": endpoint_sensitivity,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for API request: {', '.join(missing_specific)}"
            }
        
        # Validate standardized values for event-specific fields
        standardized_validations = [
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
        
        # Determine event type and status based on success flag
        event_type = EventType.API_REQUEST_SUCCESS if request_successful else EventType.API_REQUEST_FAILURE
        status = Status.SUCCESS if request_successful else Status.FAILURE
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.API_ENDPOINT_ACCESS,
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
            # Event-specific fields
            auth_protocol=auth_protocol,
            endpoint_path=endpoint_path,
            http_method=http_method,
            endpoint_sensitivity=endpoint_sensitivity,
            detail=detail,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_api_request_processed: {str(e)}"}

# ==================================
# == Customer Data Actions Functions
# ==================================

def log_multi_record_access(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    endpoint_path: str = "",
    data_sensitivity_level: str = "",
    record_count: Union[int, str] = "",
    customer_id_list: Union[List[str], str] = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Action type
    action_type: str = "view"  # "view", "modify", "export", "download"
) -> Dict[str, str]:
    """
    Logs multi-record data access events.
    
    Required log_specifics fields:
    - endpoint_path: The API endpoint used for the action
    - data_sensitivity_level: The sensitivity of the data being accessed
    - record_count: The number of records affected/accessed
    - customer_id_list: A list of the unique customer IDs accessed
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "endpoint_path": endpoint_path,
            "data_sensitivity_level": data_sensitivity_level,
            "record_count": str(record_count) if record_count else "",
            "customer_id_list": str(customer_id_list) if customer_id_list else "",
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for multi-record access: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on action
        event_type_map = {
            "view": EventType.CUSTOMER_LIST_VIEW,
            "modify": EventType.CUSTOMER_LIST_MODIFY,
            "export": EventType.REPORT_EXPORT,
            "download": EventType.REPORT_DOWNLOAD,
        }
        event_type = event_type_map.get(action_type, EventType.CUSTOMER_LIST_VIEW)
        
        # Convert record_count to int if it's a string
        try:
            record_count_int = int(record_count) if record_count else 0
        except (ValueError, TypeError):
            return {"status": "failure", "message": "record_count must be a valid integer"}
        
        # Convert customer_id_list to list if it's a string
        if isinstance(customer_id_list, str):
            try:
                import json
                customer_id_list = json.loads(customer_id_list)
            except:
                customer_id_list = [customer_id_list]  # Single ID as string
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.CUSTOMER_DATA_ACTIONS,
            status=Status.SUCCESS,
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
            # Event-specific fields
            endpoint_path=endpoint_path,
            data_sensitivity_level=data_sensitivity_level,
            record_count=record_count_int,
            customer_id_list=customer_id_list,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_multi_record_access: {str(e)}"}

def log_single_record_access(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    customer_id: str = "",
    fields_accessed: Union[List[str], str] = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Action type
    action_type: str = "view"  # "view", "modify"
) -> Dict[str, str]:
    """
    Logs single record view/modify events.
    
    Required log_specifics fields:
    - customer_id: The unique ID of the customer whose record was accessed
    - fields_accessed: A list of the specific fields that were viewed or modified
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "customer_id": customer_id,
            "fields_accessed": str(fields_accessed) if fields_accessed else "",
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for single record access: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on action
        event_type = EventType.CUSTOMER_RECORD_VIEW if action_type == "view" else EventType.CUSTOMER_RECORD_MODIFY
        
        # Convert fields_accessed to list if it's a string
        if isinstance(fields_accessed, str):
            try:
                import json
                fields_accessed = json.loads(fields_accessed)
            except:
                fields_accessed = [fields_accessed]  # Single field as string
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.CUSTOMER_DATA_ACTIONS,
            status=Status.SUCCESS,
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
            # Event-specific fields
            customer_id=customer_id,
            fields_accessed=fields_accessed,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_single_record_access: {str(e)}"}

# ==================================
# == Key Configuration Changes Functions
# ==================================

def log_mfa_status_change(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",
    mfa_id: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # MFA change type
    mfa_change_type: str = "enabled"  # "enabled", "disabled", "device_added", "device_removed"
) -> Dict[str, str]:
    """
    Logs MFA status change events.
    
    Required log_specifics fields:
    - target_object: The User ID or object whose MFA status was changed
    - mfa_id: The unique ID of the MFA device that was impacted
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_object": target_object,
            "mfa_id": mfa_id,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for MFA status change: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on change type
        event_type_map = {
            "enabled": EventType.MFA_STATUS_ENABLED,
            "disabled": EventType.MFA_STATUS_DISABLED,
            "device_added": EventType.MFA_DEVICE_ADDED,
            "device_removed": EventType.MFA_DEVICE_REMOVED,
        }
        event_type = event_type_map.get(mfa_change_type, EventType.MFA_STATUS_ENABLED)
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=Status.SUCCESS,
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
            # Event-specific fields
            target_object=target_object,
            mfa_id=mfa_id,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_mfa_status_change: {str(e)}"}

def log_password_change_reset(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Password action type
    password_action: str = "change"  # "change", "reset"
) -> Dict[str, str]:
    """
    Logs password change/reset events.
    
    Required log_specifics fields:
    - target_object: The User ID whose password was changed or reset
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_object": target_object,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for password change/reset: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on password action
        event_type = EventType.PASSWORD_CHANGE if password_action == "change" else EventType.PASSWORD_RESET
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=Status.SUCCESS,
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
            # Event-specific fields
            target_object=target_object,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_password_change_reset: {str(e)}"}

def log_api_key_lifecycle(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Lifecycle action
    lifecycle_action: str = "created"  # "created", "revoked", "permissions_modified"
) -> Dict[str, str]:
    """
    Logs API key lifecycle events.
    
    Required log_specifics fields:
    - target_object: The API Client ID or key that was affected
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_object": target_object,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for API key lifecycle: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on lifecycle action
        event_type_map = {
            "created": EventType.API_KEY_CREATED,
            "revoked": EventType.API_KEY_REVOKED,
            "permissions_modified": EventType.API_KEY_PERMISSIONS_MODIFIED,
        }
        event_type = event_type_map.get(lifecycle_action, EventType.API_KEY_CREATED)
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=Status.SUCCESS,
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
            # Event-specific fields
            target_object=target_object,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_api_key_lifecycle: {str(e)}"}

def log_auth_mechanism_modification(
    # Base log fields (required but with defaults to avoid crashes)
    timestamp: str = "",
    actor_identifier: str = "",
    actor_type: str = "",
    session_id: str = "",
    cloud_env_type: str = "",
    service_name: str = "",
    cloud_env_unique_id: str = "",
    cloud_env_name: str = "",
    service_account_id: str = "",
    # Event-specific required fields
    target_object: str = "",
    # Optional fields
    source_ip_address: str = "",
    cloud_service_api_type: str = "",
    # Modification type
    modification_type: str = "sso_config_created"  # "sso_config_created", "sso_config_modified", "sso_config_deleted", "local_auth_enabled", "local_auth_disabled"
) -> Dict[str, str]:
    """
    Logs authentication mechanism modification events.
    
    Required log_specifics fields:
    - target_object: The configuration object that was changed (e.g., "sso_assertion_url", "local_authentication")
    """
    try:
        # Validate event-specific required fields
        event_specific_required = {
            "target_object": target_object,
        }
        
        missing_specific = [field for field, value in event_specific_required.items() 
                          if not value or value.strip() == ""]
        
        if missing_specific:
            return {
                "status": "failure", 
                "message": f"Required log_specifics fields missing for auth mechanism modification: {', '.join(missing_specific)}"
            }
        
        # Determine event type based on modification type
        event_type_map = {
            "sso_config_created": EventType.SSO_CONFIG_CREATED,
            "sso_config_modified": EventType.SSO_CONFIG_MODIFIED,
            "sso_config_deleted": EventType.SSO_CONFIG_DELETED,
            "local_auth_enabled": EventType.LOCAL_AUTH_CONFIG_ENABLED,
            "local_auth_disabled": EventType.LOCAL_AUTH_CONFIG_DISABLED,
        }
        event_type = event_type_map.get(modification_type, EventType.SSO_CONFIG_CREATED)
        
        # Create the log event
        event = _create_base_log_event(
            timestamp=timestamp,
            event_type=event_type,
            log_category=LogCategory.KEY_CONFIG_CHANGES,
            status=Status.SUCCESS,
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
            # Event-specific fields
            target_object=target_object,
        )
        
        if "status" in event and event["status"] == "failure":
            return event  # Return validation error
        
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_auth_mechanism_modification: {str(e)}"}