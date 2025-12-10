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
    log_multi_record_access,
    log_single_record_access,
    
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

__version__ = "1.1.0"
__author__ = "Sunrun Security Team"
__description__ = "Python module for structured security logging to AWS SNS"

# Module-level convenience imports for easier usage
# Users can import like: import sr_sec_py_sns_logger as SecurityLogging
# Then use: SecurityLogging.log_user_login(...)
