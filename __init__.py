# sr-sec-py-sns-logger - Python Security Logging Module
# 
# This module provides structured security logging to AWS SNS for centralized monitoring.
# All security events are consistently formatted and delivered to your security pipeline.

from .security_logging_sns import (
    # Initialization
    init_security_logging,
    
    # Fire-and-forget functionality (NEW)
    fire_and_forget,
    set_security_logging_error_handler,
    
    # Authentication & Session functions
    log_user_login,
    log_mfa_challenge,
    log_user_logout,
    
    # Authorization & Access functions
    log_permission_role_change,
    log_user_status_change,
    log_impersonation_event,
    log_user_invite_event,
    
    # API Endpoint Access functions
    log_api_request,
    
    # Customer Data Actions functions
    log_record_access,
    
    # Key Configuration Changes functions
    log_mfa_status_change,
    log_password_change_reset,
    log_api_key_lifecycle,
    log_auth_mechanism_modification,
)

from .security_log_fields import (
    # Status values
    Status,
    
    # Actor types
    ActorType,
    
    # Log categories
    LogCategory,
    
    # Event types
    EventType,
    
    # Authentication protocols
    AuthProtocol,
    
    # Detail values
    Detail,
    
    # MFA types
    MfaType,
    
    # HTTP methods
    HttpMethod,
    
    # Cloud environment types
    CloudEnvType,
    
    # Cloud service API types
    CloudServiceApiType,
    
    # Data sensitivity levels
    DataSensitivityLevel,
    
    # Endpoint sensitivity levels
    EndpointSensitivity,
    
    # User roles
    UserRole,
    
    # Invite status values
    InviteStatus,
    
    # Validation lists
    VALID_EVENT_TYPES,
)

from .context_helpers import (
    # Main context creation functions
    create_security_context,
    create_server_context,
    create_lambda_context,
    
    # Individual extraction functions
    extract_user_agent,
    extract_source_ip,
    extract_endpoint_path,
    extract_http_method,
    extract_actor_identifier,
    extract_session_id,
    extract_cloud_env_type,
    extract_cloud_env_name,
    extract_cloud_env_unique_id,
    extract_service_name,
    extract_service_account_id,
    
    # Diagnostic helpers (informational, no exceptions)
    get_missing_context_fields,
    warn_missing_context_fields,
    diagnose_security_context,
    REQUIRED_CONTEXT_FIELDS,
)

__version__ = "2.0.2"
__author__ = "Sunrun Security Team"
__description__ = "Python module for structured security logging to AWS SNS"

# Module-level convenience imports for easier usage
# Users can import like: import sr_sec_py_sns_logger as SecurityLogging
# Then use: SecurityLogging.log_user_login(...)
