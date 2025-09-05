# File: security_logging_sns.py

import os
from typing import Dict, Any, Optional, List
from security_log_fields import (
    ActionType, AuthorizationStatus, AuthProtocol, UserType, EventType, ChangeType
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
# == Helper Functions to Create Log Events
# ==================================

def _create_log_event(
    base_log_details: Dict[str, Any],
    log_category: str,
    event_type: str,
    **kwargs: Any
) -> Dict[str, Any]:
    """Helper function to combine base and event-specific log details."""
    log_details = {
        "log_type": "security",
        "log_category": log_category,
        "event_type": event_type,
        **kwargs,
    }
    return {**base_log_details, **log_details}

# ==================================
# == Authentication & Session
# ==================================

def log_user_login(
    base_log_details: Dict[str, Any],
    status: str,
    session_id: str,
    user_identifier: str,
    user_type: str,
    source_ip_address: str,
    user_agent: str,
    user_role: str,
    device_id: Optional[str] = None,
    context: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, str]:
    """Logs User Login Success and Failure events."""
    try:
        event_type = EventType.LOGIN_SUCCESS if status == AuthorizationStatus.SUCCESS else EventType.LOGIN_FAILURE
        log_details = {
            "status": status,
            "session_id": session_id,
            "user_identifier": user_identifier,
            "user_type": user_type,
            "source_ip_address": source_ip_address,
            "user_agent": user_agent,
            "user_role": user_role,
        }
        if device_id: log_details["device_id"] = device_id
        if context: log_details["context"] = context
        if reason: log_details["reason"] = reason

        event = _create_log_event(
            base_log_details,
            log_category="authn_n_session",
            event_type=event_type,
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_login: {str(e)}"}

def log_mfa_challenge(
    base_log_details: Dict[str, Any],
    status: str,
    session_id: str,
    user_identifier: str,
    user_type: str,
    source_ip_address: str,
    user_agent: str,
    user_role: str,
    mfa_type: str,
    device_id: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, str]:
    """Logs MFA Challenge events."""
    try:
        log_details = {
            "status": status,
            "session_id": session_id,
            "user_identifier": user_identifier,
            "user_type": user_type,
            "source_ip_address": source_ip_address,
            "user_agent": user_agent,
            "user_role": user_role,
            "mfa_type": mfa_type,
        }
        if device_id: log_details["device_id"] = device_id
        if reason: log_details["reason"] = reason

        event = _create_log_event(
            base_log_details,
            log_category="authn_n_session",
            event_type=EventType.MFA_CHALLENGE,
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_mfa_challenge: {str(e)}"}

def log_user_logout(
    base_log_details: Dict[str, Any],
    session_id: str,
    user_identifier: str,
    user_type: str,
    source_ip_address: str,
    user_agent: str,
    reason: str
) -> Dict[str, str]:
    """Logs User Logout events."""
    try:
        log_details = {
            "status": AuthorizationStatus.SUCCESS,
            "session_id": session_id,
            "user_identifier": user_identifier,
            "user_type": user_type,
            "source_ip_address": source_ip_address,
            "user_agent": user_agent,
            "reason": reason,
        }
        event = _create_log_event(
            base_log_details,
            log_category="authn_n_session",
            event_type=EventType.LOGOUT,
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_logout: {str(e)}"}

# ==================================
# == Authorization & Access
# ==================================

def log_permission_change(
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    target_user_identifier: str,
    session_id: str,
    object_changed: str,
    previous_value: Any,
    new_value: Any
) -> Dict[str, str]:
    """Logs a permission or role change event."""
    try:
        log_details = {
            "actor_user_identifier": actor_user_identifier,
            "target_user_identifier": target_user_identifier,
            "session_id": session_id,
            "object_changed": object_changed,
            "previous_value": previous_value,
            "new_value": new_value,
        }
        event = _create_log_event(
            base_log_details,
            log_category="authz_n_access",
            event_type="permission_change",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_permission_change: {str(e)}"}

def log_user_status_change(
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    target_user_identifier: str,
    action_type: str,
    actor_user_type: str,
    reason: Optional[str] = None
) -> Dict[str, str]:
    """Logs a user status change event."""
    try:
        log_details = {
            "actor_user_identifier": actor_user_identifier,
            "target_user_identifier": target_user_identifier,
            "action_type": action_type,
            "actor_user_type": actor_user_type,
        }
        if reason: log_details["reason"] = reason
        event = _create_log_event(
            base_log_details,
            log_category="authz_n_access",
            event_type="user_status_change",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_user_status_change: {str(e)}"}

def log_impersonation_event(
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    actor_session_id: str,
    target_user_identifier: str,
    action_type: str,
    actor_user_type: str
) -> Dict[str, str]:
    """Logs an impersonation start/stop event."""
    try:
        log_details = {
            "actor_user_identifier": actor_user_identifier,
            "actor_session_id": actor_session_id,
            "target_user_identifier": target_user_identifier,
            "action_type": action_type,
            "actor_user_type": actor_user_type,
        }
        event = _create_log_event(
            base_log_details,
            log_category="authz_n_access",
            event_type="impersonation_event",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_impersonation_event: {str(e)}"}

# ==================================
# == API Endpoint Access
# ==================================

def log_api_request_processed(
    base_log_details: Dict[str, Any],
    source_ip_address: str,
    auth_protocol: str,
    client_id: str,
    client_type: str,
    endpoint_path: str,
    http_method: str,
    authorization_status: str,
    endpoint_sensitivity: str,
    session_id: Optional[str] = None,
    reason: Optional[str] = None
) -> Dict[str, str]:
    """Logs an API request processed event."""
    try:
        log_details = {
            "source_ip_address": source_ip_address,
            "auth_protocol": auth_protocol,
            "client_id": client_id,
            "client_type": client_type,
            "endpoint_path": endpoint_path,
            "http_method": http_method,
            "authorization_status": authorization_status,
            "endpoint_sensitivity": endpoint_sensitivity,
        }
        if session_id: log_details["session_id"] = session_id
        if reason: log_details["reason"] = reason
        event = _create_log_event(
            base_log_details,
            log_category="api_endpoint_access",
            event_type="api_request_processed",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_api_request_processed: {str(e)}"}

# ==================================
# == Customer Data Actions
# ==================================

def log_multi_record_access(
    base_log_details: Dict[str, Any],
    user_identifier: str,
    source_ip_address: str,
    action_type: str,
    record_count: int,
    session_id: str,
    actor_user_type: str,
    endpoint_path: Optional[str] = None,
    data_sensitivity_level: Optional[str] = "Confidential-PII"
) -> Dict[str, str]:
    """Logs a multi-record data access event."""
    try:
        log_details = {
            "user_identifier": user_identifier,
            "source_ip_address": source_ip_address,
            "action_type": action_type,
            "record_count": record_count,
            "session_id": session_id,
            "actor_user_type": actor_user_type,
        }
        if endpoint_path: log_details["endpoint_path"] = endpoint_path
        if data_sensitivity_level: log_details["data_sensitivity_level"] = data_sensitivity_level
        event = _create_log_event(
            base_log_details,
            log_category="customer_data_actions",
            event_type="multi_record_access",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_multi_record_access: {str(e)}"}

def log_single_record_access(
    base_log_details: Dict[str, Any],
    user_identifier: str,
    source_ip_address: str,
    customer_id: str,
    action_type: str,
    fields_accessed: List[str],
    session_id: str,
    actor_user_type: str
) -> Dict[str, str]:
    """Logs a single record view/modify event."""
    try:
        log_details = {
            "user_identifier": user_identifier,
            "source_ip_address": source_ip_address,
            "customer_id": customer_id,
            "action_type": action_type,
            "fields_accessed": fields_accessed,
            "session_id": session_id,
            "actor_user_type": actor_user_type,
        }
        event = _create_log_event(
            base_log_details,
            log_category="customer_data_actions",
            event_type="single_record_access",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_single_record_access: {str(e)}"}

# ==================================
# == Key Configuration Changes
# ==================================

def log_key_configuration_change(
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    actor_session_id: str,
    target_object: str,
    change_type: str,
    status: str,
    actor_user_type: str,
    mfa_id: Optional[str] = None
) -> Dict[str, str]:
    """Logs changes to MFA, passwords, API keys, or auth mechanisms."""
    try:
        log_details = {
            "actor_user_identifier": actor_user_identifier,
            "actor_session_id": actor_session_id,
            "target_object": target_object,
            "change_type": change_type,
            "status": status,
            "actor_user_type": actor_user_type,
        }
        if mfa_id: log_details["mfa_id"] = mfa_id
        event = _create_log_event(
            base_log_details,
            log_category="key_config_changes",
            event_type="key_configuration_change",
            **log_details
        )
        return _get_publisher().publish_message(event)
    except Exception as e:
        return {"status": "failure", "message": f"Error in log_key_configuration_change: {str(e)}"}