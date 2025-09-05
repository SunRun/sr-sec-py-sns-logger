# File: security_logging_sns.py

import os
import json
import boto3
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from security_log_fields import (
    ActionType, AuthorizationStatus, AuthProtocol, UserType, EventType, ChangeType
)

class SNSPublisher:
    """A client for publishing security logs to an AWS SNS topic."""
    
    def __init__(self, topic_arn: str):
        self.topic_arn = topic_arn
        # Initialize the SNS client. This should be done once for the application.
        self.sns_client = boto3.client('sns')
    
    def _publish_message(self, log_details: Dict[str, Any]):
        """
        Publishes a single JSON log message to the configured SNS topic.
        Includes base and event-specific details.
        """
        try:
            # Add a timestamp to the log record
            log_details['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            # The message must be a JSON string
            message = json.dumps(log_details)
            
            # Publish the message to the SNS topic
            self.sns_client.publish(
                TopicArn=self.topic_arn,
                Message=message,
            )
        except Exception as e:
            # Handle potential SNS publishing errors (e.g., permissions, topic not found)
            print(f"Error publishing security log to SNS: {e}")
            # Optionally, re-raise the exception or log it to a different stream
            # for developer debugging, as this is a non-critical path.

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
    sns_publisher: SNSPublisher,
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
):
    """Logs User Login Success and Failure events."""
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
    sns_publisher._publish_message(event)

def log_mfa_challenge(
    sns_publisher: SNSPublisher,
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
):
    """Logs MFA Challenge events."""
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
    sns_publisher._publish_message(event)

def log_user_logout(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    session_id: str,
    user_identifier: str,
    user_type: str,
    source_ip_address: str,
    user_agent: str,
    reason: str
):
    """Logs User Logout events."""
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
    sns_publisher._publish_message(event)

# ==================================
# == Authorization & Access
# ==================================

def log_permission_change(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    target_user_identifier: str,
    session_id: str,
    object_changed: str,
    previous_value: Any,
    new_value: Any
):
    """Logs a permission or role change event."""
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
    sns_publisher._publish_message(event)

def log_user_status_change(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    target_user_identifier: str,
    action_type: str,
    actor_user_type: str,
    reason: Optional[str] = None
):
    """Logs a user status change event."""
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
    sns_publisher._publish_message(event)

def log_impersonation_event(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    actor_session_id: str,
    target_user_identifier: str,
    action_type: str,
    actor_user_type: str
):
    """Logs an impersonation start/stop event."""
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
    sns_publisher._publish_message(event)

# ==================================
# == API Endpoint Access
# ==================================

def log_api_request_processed(
    sns_publisher: SNSPublisher,
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
):
    """Logs an API request processed event."""
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
    sns_publisher._publish_message(event)

# ==================================
# == Customer Data Actions
# ==================================

def log_multi_record_access(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    user_identifier: str,
    source_ip_address: str,
    action_type: str,
    record_count: int,
    session_id: str,
    actor_user_type: str,
    endpoint_path: Optional[str] = None,
    data_sensitivity_level: Optional[str] = "Confidential-PII"
):
    """Logs a multi-record data access event."""
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
    sns_publisher._publish_message(event)

def log_single_record_access(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    user_identifier: str,
    source_ip_address: str,
    customer_id: str,
    action_type: str,
    fields_accessed: List[str],
    session_id: str,
    actor_user_type: str
):
    """Logs a single record view/modify event."""
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
    sns_publisher._publish_message(event)

# ==================================
# == Key Configuration Changes
# ==================================

def log_key_configuration_change(
    sns_publisher: SNSPublisher,
    base_log_details: Dict[str, Any],
    actor_user_identifier: str,
    actor_session_id: str,
    target_object: str,
    change_type: str,
    status: str,
    actor_user_type: str,
    mfa_id: Optional[str] = None
):
    """Logs changes to MFA, passwords, API keys, or auth mechanisms."""
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
    sns_publisher._publish_message(event)