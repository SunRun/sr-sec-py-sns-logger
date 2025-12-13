# File: security_log_fields.py
"""
Security Log Fields Module

This module contains all standardized constants for security logging.
Use these constants to ensure consistent values across all security log events.

Example:
    >>> from security_log_fields import Status, EventType, ActorType
    >>> 
    >>> # Successful login event
    >>> event_type = EventType.LOGIN_ATTEMPT  # "login_attempt"
    >>> status = Status.SUCCESS               # "status.general.success"
    >>> actor_type = ActorType.HUMAN_INTERNAL # "actor.human.internal"
"""


class Status:
    """
    Status values for event outcomes.
    Use these constants to indicate success or failure of security events.
    
    Example:
        >>> from security_log_fields import Status
        >>> 
        >>> # Successful login
        >>> status = Status.SUCCESS  # "status.general.success"
        >>> 
        >>> # Failed login attempt
        >>> status = Status.FAILURE  # "status.general.failure"
    """
    SUCCESS = "status.general.success"
    """Indicates a successful event outcome. Example: "status.general.success" """
    
    FAILURE = "status.general.failure"
    """Indicates a failed event outcome. Example: "status.general.failure" """


class ActorType:
    """
    Actor types define WHO or WHAT is performing the action.
    
    Choose the type that best matches the entity initiating the event:
    - HUMAN: A person directly interacting with the system
    - SERVICE: An application, microservice, or automated agent acting on behalf of someone
    - SYSTEM: The application itself performing automated actions
    
    Then specify the relationship (INTERNAL/PARTNER/CUSTOMER)
    
    Example:
        >>> from security_log_fields import ActorType
        >>> 
        >>> # Sunrun employee logging in
        >>> actor_type = ActorType.HUMAN_INTERNAL  # "actor.human.internal"
        >>> 
        >>> # Partner's API integration
        >>> actor_type = ActorType.SERVICE_PARTNER  # "actor.service.partner"
        >>> 
        >>> # Scheduled cleanup job
        >>> actor_type = ActorType.SYSTEM_SELF  # "actor.system.self"
    """
    # Sunrun employee or contractor (e.g., admin, developer, support rep)
    HUMAN_INTERNAL = "actor.human.internal"
    """Sunrun employee or contractor. Example: "actor.human.internal" """
    
    # Partner organization employee (e.g., installer, vendor user)
    HUMAN_PARTNER = "actor.human.partner"
    """Partner organization employee. Example: "actor.human.partner" """
    
    # Sunrun customer or homeowner
    HUMAN_CUSTOMER = "actor.human.customer"
    """Sunrun customer or homeowner. Example: "actor.human.customer" """
    
    # Internal Sunrun service/microservice acting on behalf of a user
    SERVICE_INTERNAL = "actor.service.internal"
    """Internal service/microservice. Example: "actor.service.internal" """
    
    # Partner's service or API integration
    SERVICE_PARTNER = "actor.service.partner"
    """Partner's service or API. Example: "actor.service.partner" """
    
    # Customer-owned service or application
    SERVICE_CUSTOMER = "actor.service.customer"
    """Customer-owned service. Example: "actor.service.customer" """
    
    # The application itself performing scheduled/automated tasks
    SYSTEM_SELF = "actor.system.self"
    """Application performing automated tasks. Example: "actor.system.self" """


class LogCategory:
    """
    Log categories for grouping security events.
    Each logging function automatically sets the appropriate category.
    
    Example:
        >>> from security_log_fields import LogCategory
        >>> 
        >>> # Authentication events
        >>> log_category = LogCategory.AUTHN_SESSION  # "authn_n_session"
    """
    AUTHN_SESSION = "authn_n_session"
    """Authentication and session events (login, logout, MFA)"""
    
    AUTHZ_ACCESS = "authz_n_access"
    """Authorization and access control events"""
    
    API_ENDPOINT_ACCESS = "api_endpoint_access"
    """API endpoint access events"""
    
    CUSTOMER_DATA_ACTIONS = "customer_data_actions"
    """Customer data access events"""
    
    KEY_CONFIG_CHANGES = "key_config_changes"
    """Configuration changes (MFA, passwords, API keys)"""


class EventType:
    """
    Event types for security logging.
    Use these constants when specifying the event_type field.
    
    Example:
        >>> from security_log_fields import EventType, Status
        >>> 
        >>> # User login event
        >>> event_type = EventType.LOGIN_ATTEMPT  # "login_attempt"
        >>> status = Status.SUCCESS  # Indicates successful login
        >>> 
        >>> # Record data access
        >>> event_type = EventType.RECORD_ACCESS  # "record_access"
    """
    # Authentication & Session
    LOGIN_ATTEMPT = "login_attempt"
    """Login attempt event. Use with Status.SUCCESS or Status.FAILURE. Example: "login_attempt" """
    
    USER_LOGOUT = "user_logout"
    """User logout event. Example: "user_logout" """
    
    MFA_CHALLENGE = "mfa_challenge"
    """MFA challenge event. Example: "mfa_challenge" """
    
    # Authorization & Access
    PERMISSION_CHANGE = "permission_change"
    """Permission or role change event. Example: "permission_change" """
    
    USER_STATUS_CHANGE = "user_status_change"
    """User status change event. Example: "user_status_change" """
    
    IMPERSONATION_EVENT = "impersonation_event"
    """Impersonation event. Example: "impersonation_event" """
    
    USER_INVITE_EVENT = "user_invite_event"
    """User invitation event. Example: "user_invite_event" """
    
    # API Endpoint Access
    API_REQUEST_PROCESSED = "api_request_processed"
    """API request processed event. Example: "api_request_processed" """
    
    # Customer Data Actions
    RECORD_ACCESS = "record_access"
    """Record access event (single or multiple records). Example: "record_access" """
    
    # Key Configuration Changes
    MFA_STATUS_CHANGE = "mfa_status_change"
    """MFA status change event. Example: "mfa_status_change" """
    
    PASSWORD_CHANGE_RESET = "password_change_reset"
    """Password change or reset event. Example: "password_change_reset" """
    
    API_KEY_LIFECYCLE = "api_key_lifecycle"
    """API key lifecycle event. Example: "api_key_lifecycle" """
    
    AUTH_MECHANISM_MODIFICATION = "auth_mechanism_modification"
    """Authentication mechanism modification. Example: "auth_mechanism_modification" """


class AuthProtocol:
    """
    Authentication protocols for specifying how authentication was performed.
    
    Example:
        >>> from security_log_fields import AuthProtocol
        >>> 
        >>> # OAuth2 JWT authentication
        >>> auth_protocol = AuthProtocol.OAUTH2_JWT  # "auth.protocol.oauth2.jwt"
        >>> 
        >>> # API key authentication
        >>> auth_protocol = AuthProtocol.API_KEY  # "auth.protocol.api_key"
    """
    # Basic username/password authentication
    BASIC_AUTH = "auth.protocol.basic_auth"
    """HTTP Basic Authentication. Example: "auth.protocol.basic_auth" """
    
    FORM_BASED = "auth.protocol.form_based"
    """Form-based username/password login. Example: "auth.protocol.form_based" """
    
    # Token-based authentication
    API_KEY = "auth.protocol.api_key"
    """API key authentication. Example: "auth.protocol.api_key" """
    
    M2M_TOKEN = "auth.protocol.m2m_token"
    """Machine-to-machine token. Example: "auth.protocol.m2m_token" """
    
    SESSION_COOKIE = "auth.protocol.session_cookie"
    """Session cookie authentication. Example: "auth.protocol.session_cookie" """
    
    # OAuth2 variants
    OAUTH2_JWT = "auth.protocol.oauth2.jwt"
    """OAuth2 with JWT tokens. Example: "auth.protocol.oauth2.jwt" """
    
    OAUTH2_CLIENT_CREDENTIALS = "auth.protocol.oauth2.client_credentials"
    """OAuth2 client credentials flow. Example: "auth.protocol.oauth2.client_credentials" """
    
    OAUTH2_AUTHORIZATION_CODE = "auth.protocol.oauth2.authorization_code"
    """OAuth2 authorization code flow. Example: "auth.protocol.oauth2.authorization_code" """
    
    OAUTH2_IMPLICIT = "auth.protocol.oauth2.implicit"
    """OAuth2 implicit flow (deprecated). Example: "auth.protocol.oauth2.implicit" """
    
    OAUTH2_PASSWORD_GRANT = "auth.protocol.oauth2.password_grant"
    """OAuth2 password grant flow. Example: "auth.protocol.oauth2.password_grant" """
    
    # SSO protocols
    SAML = "auth.protocol.saml"
    """SAML authentication. Example: "auth.protocol.saml" """
    
    OIDC = "auth.protocol.oidc"
    """OpenID Connect authentication. Example: "auth.protocol.oidc" """
    
    # Special cases
    NONE = "auth.protocol.none"
    """No authentication (public endpoints). Example: "auth.protocol.none" """


class Detail:
    """
    Detail values for providing context on events.
    Use these constants for the detail field to explain what happened.
    
    Example:
        >>> from security_log_fields import Detail
        >>> 
        >>> # Failed login due to invalid credentials
        >>> detail = Detail.INVALID_CREDENTIALS  # "detail.auth.invalid_credentials"
        >>> 
        >>> # User-initiated logout
        >>> detail = Detail.USER_INITIATED  # "detail.trigger.user_initiated"
    """
    # Authentication failure reasons
    INVALID_CREDENTIALS = "detail.auth.invalid_credentials"
    """Invalid username or password. Example: "detail.auth.invalid_credentials" """
    
    ACCOUNT_LOCKED = "detail.auth.account_locked"
    """Account is locked. Example: "detail.auth.account_locked" """
    
    IP_RESTRICTED = "detail.auth.ip_restricted"
    """IP address restricted. Example: "detail.auth.ip_restricted" """
    
    MFA_REQUIRED = "detail.auth.mfa_required"
    """MFA is required. Example: "detail.auth.mfa_required" """
    
    POLICY_VIOLATION = "detail.auth.policy_violation"
    """Policy violation. Example: "detail.auth.policy_violation" """
    
    CAPTCHA_FAILURE = "detail.auth.captcha_failure"
    """CAPTCHA failed. Example: "detail.auth.captcha_failure" """
    
    TOKEN_EXPIRED = "detail.auth.token_expired"
    """Token has expired. Example: "detail.auth.token_expired" """
    
    TOKEN_INVALID = "detail.auth.token_invalid"
    """Token is invalid. Example: "detail.auth.token_invalid" """
    
    UNAUTHORIZED_ACCESS = "detail.auth.unauthorized_access"
    """Unauthorized access attempt. Example: "detail.auth.unauthorized_access" """
    
    RATE_LIMIT_EXCEEDED = "detail.auth.rate_limit_exceeded"
    """Rate limit exceeded. Example: "detail.auth.rate_limit_exceeded" """
    
    # Action/Status Change Triggers
    USER_INITIATED = "detail.trigger.user_initiated"
    """Action initiated by user. Example: "detail.trigger.user_initiated" """
    
    ADMIN_INITIATED = "detail.trigger.admin_initiated"
    """Action initiated by admin. Example: "detail.trigger.admin_initiated" """
    
    SYSTEM_AUTOMATED = "detail.trigger.system_automated"
    """Automated system action. Example: "detail.trigger.system_automated" """
    
    SYSTEM_POLICY_VIOLATION = "detail.trigger.system_policy_violation"
    """Triggered by policy violation. Example: "detail.trigger.system_policy_violation" """
    
    SESSION_TIMEOUT = "detail.trigger.session_timeout"
    """Session timeout. Example: "detail.trigger.session_timeout" """
    
    CONCURRENT_SESSION = "detail.trigger.concurrent_session"
    """Concurrent session detected. Example: "detail.trigger.concurrent_session" """
    
    FAILED_ATTEMPTS_THRESHOLD = "detail.trigger.failed_attempts_threshold"
    """Failed attempts threshold reached. Example: "detail.trigger.failed_attempts_threshold" """
    
    # General System/Operational
    INTERNAL_ERROR = "detail.system.internal_error"
    """Internal system error. Example: "detail.system.internal_error" """
    
    SERVICE_UNAVAILABLE = "detail.system.service_unavailable"
    """Service unavailable. Example: "detail.system.service_unavailable" """
    
    MAINTENANCE = "detail.system.maintenance"
    """System maintenance. Example: "detail.system.maintenance" """
    
    INVALID_REQUEST = "detail.client.invalid_request"
    """Invalid request from client. Example: "detail.client.invalid_request" """
    
    NOT_APPLICABLE = "detail.not_applicable"
    """Not applicable. Example: "detail.not_applicable" """
    
    # API Key Lifecycle Actions
    API_KEY_CREATED = "detail.api_key.created"
    """API key created. Example: "detail.api_key.created" """
    
    API_KEY_REVOKED = "detail.api_key.revoked"
    """API key revoked. Example: "detail.api_key.revoked" """
    
    API_KEY_PERMISSIONS_MODIFIED = "detail.api_key.permissions_modified"
    """API key permissions modified. Example: "detail.api_key.permissions_modified" """
    
    # Auth Mechanism Modification Types
    SSO_CONFIG_CREATED = "detail.auth.sso_config_created"
    """SSO configuration created. Example: "detail.auth.sso_config_created" """
    
    SSO_CONFIG_MODIFIED = "detail.auth.sso_config_modified"
    """SSO configuration modified. Example: "detail.auth.sso_config_modified" """
    
    SSO_CONFIG_DELETED = "detail.auth.sso_config_deleted"
    """SSO configuration deleted. Example: "detail.auth.sso_config_deleted" """
    
    LOCAL_AUTH_ENABLED = "detail.auth.local_auth_enabled"
    """Local authentication enabled. Example: "detail.auth.local_auth_enabled" """
    
    LOCAL_AUTH_DISABLED = "detail.auth.local_auth_disabled"
    """Local authentication disabled. Example: "detail.auth.local_auth_disabled" """
    
    # User Status Actions
    USER_DISABLED = "detail.action.user_disabled"
    """User disabled. Example: "detail.action.user_disabled" """
    
    USER_ENABLED = "detail.action.user_enabled"
    """User enabled. Example: "detail.action.user_enabled" """
    
    USER_DELETED = "detail.action.user_deleted"
    """User deleted. Example: "detail.action.user_deleted" """
    
    USER_LOCKED = "detail.action.user_locked"
    """User locked. Example: "detail.action.user_locked" """
    
    USER_UNLOCKED = "detail.action.user_unlocked"
    """User unlocked. Example: "detail.action.user_unlocked" """
    
    # Impersonation Actions
    IMPERSONATION_START = "detail.action.impersonation_start"
    """Impersonation started. Example: "detail.action.impersonation_start" """
    
    IMPERSONATION_STOP = "detail.action.impersonation_stop"
    """Impersonation stopped. Example: "detail.action.impersonation_stop" """
    
    # Customer Data Actions
    VIEW_LIST = "detail.action.view_list"
    """Viewing a list of records. Example: "detail.action.view_list" """
    
    MODIFY_CUSTOMER_DATA = "detail.action.modify_customer_data"
    """Modifying customer data. Example: "detail.action.modify_customer_data" """
    
    EXPORT_REPORT = "detail.action.export_report"
    """Exporting a report. Example: "detail.action.export_report" """
    
    VIEW_RECORD = "detail.action.view_record"
    """Viewing a single record. Example: "detail.action.view_record" """
    
    EDIT_RECORD = "detail.action.edit_record"
    """Editing a record. Example: "detail.action.edit_record" """
    
    # MFA Actions (for mfa_status_change events)
    MFA_DISABLED = "detail.action.mfa_disabled"
    """MFA disabled. Example: "detail.action.mfa_disabled" """
    
    MFA_ENABLED = "detail.action.mfa_enabled"
    """MFA enabled. Example: "detail.action.mfa_enabled" """
    
    NEW_MFA_DEVICE = "detail.action.new_mfa_device"
    """New MFA device enrolled. Example: "detail.action.new_mfa_device" """
    
    # MFA Challenge failure reasons (for mfa_challenge events)
    MFA_INVALID_CODE = "detail.mfa.invalid_code"
    """Invalid MFA code. Example: "detail.mfa.invalid_code" """
    
    MFA_EXPIRED_CODE = "detail.mfa.expired_code"
    """MFA code expired. Example: "detail.mfa.expired_code" """
    
    MFA_DEVICE_NOT_ENROLLED = "detail.mfa.device_not_enrolled"
    """MFA device not enrolled. Example: "detail.mfa.device_not_enrolled" """
    
    MFA_TOO_MANY_ATTEMPTS = "detail.mfa.too_many_attempts"
    """Too many MFA attempts. Example: "detail.mfa.too_many_attempts" """
    
    # Password Actions
    PASSWORD_CHANGE = "detail.action.password_change"
    """Password changed. Example: "detail.action.password_change" """
    
    PASSWORD_RESET = "detail.action.password_reset"
    """Password reset. Example: "detail.action.password_reset" """
    
    # Auth Mechanism Actions
    NEW_SSO_PROVIDER = "detail.action.new_sso_provider"
    """New SSO provider added. Example: "detail.action.new_sso_provider" """
    
    ENABLE_LOCAL_AUTHN = "detail.action.enable_local_authn"
    """Local authentication enabled. Example: "detail.action.enable_local_authn" """
    
    DISABLE_SSO = "detail.action.disable_sso"
    """SSO disabled. Example: "detail.action.disable_sso" """


class MfaType:
    """
    MFA types for specifying the type of multi-factor authentication used.
    
    Example:
        >>> from security_log_fields import MfaType
        >>> 
        >>> # SMS-based MFA
        >>> mfa_type = MfaType.SMS  # "sms"
        >>> 
        >>> # Okta Verify push notification
        >>> mfa_type = MfaType.OKTA_VERIFY  # "okta_verify"
    """
    SMS = "sms"
    """SMS-based OTP. Example: "sms" """
    
    TOTP = "totp"
    """Time-based OTP (Google Authenticator, etc.). Example: "totp" """
    
    PUSH = "push"
    """Push notification. Example: "push" """
    
    EMAIL = "email"
    """Email-based OTP. Example: "email" """
    
    OKTA_VERIFY = "okta_verify"
    """Okta Verify. Example: "okta_verify" """
    
    AUTHENTICATOR_APP = "authenticator_app"
    """Authenticator app. Example: "authenticator_app" """
    
    HARDWARE_TOKEN = "hardware_token"
    """Hardware token (YubiKey, etc.). Example: "hardware_token" """
    
    BIOMETRIC = "biometric"
    """Biometric (fingerprint, face). Example: "biometric" """
    
    BACKUP_CODES = "backup_codes"
    """Backup codes. Example: "backup_codes" """


class HttpMethod:
    """
    HTTP methods for API request logging.
    
    Example:
        >>> from security_log_fields import HttpMethod
        >>> 
        >>> # GET request
        >>> http_method = HttpMethod.GET  # "http.method.GET"
    """
    GET = "http.method.GET"
    """HTTP GET. Example: "http.method.GET" """
    
    POST = "http.method.POST"
    """HTTP POST. Example: "http.method.POST" """
    
    PUT = "http.method.PUT"
    """HTTP PUT. Example: "http.method.PUT" """
    
    PATCH = "http.method.PATCH"
    """HTTP PATCH. Example: "http.method.PATCH" """
    
    DELETE = "http.method.DELETE"
    """HTTP DELETE. Example: "http.method.DELETE" """
    
    HEAD = "http.method.HEAD"
    """HTTP HEAD. Example: "http.method.HEAD" """
    
    OPTIONS = "http.method.OPTIONS"
    """HTTP OPTIONS. Example: "http.method.OPTIONS" """


class CloudEnvType:
    """
    Cloud environment types for identifying the deployment environment.
    
    Example:
        >>> from security_log_fields import CloudEnvType
        >>> 
        >>> # Production environment
        >>> cloud_env_type = CloudEnvType.PROD  # "prod"
    """
    PROD = "prod"
    """Production environment. Example: "prod" """
    
    STAGE = "stage"
    """Staging environment. Example: "stage" """
    
    TEST = "test"
    """Test environment. Example: "test" """
    
    DEV = "dev"
    """Development environment. Example: "dev" """


class CloudServiceApiType:
    """
    Cloud service API types for identifying the type of cloud service.
    
    Example:
        >>> from security_log_fields import CloudServiceApiType
        >>> 
        >>> # AWS Lambda function
        >>> cloud_service_api_type = CloudServiceApiType.AWS_LAMBDA  # "aws_lambda"
    """
    AWS_LAMBDA = "aws_lambda"
    """AWS Lambda function. Example: "aws_lambda" """
    
    GKE_NAMESPACE = "gke_namespace"
    """GKE namespace. Example: "gke_namespace" """
    
    EC2_INSTANCE = "ec2_instance"
    """EC2 instance. Example: "ec2_instance" """
    
    ECS_SERVICE = "ecs_service"
    """ECS service. Example: "ecs_service" """


class DataSensitivityLevel:
    """
    Data sensitivity levels for classifying the sensitivity of accessed data.
    
    Use these standardized levels to indicate the sensitivity of data being accessed.
    Choose the level that best matches the MOST sensitive data in the operation.
    
    Quick Decision Guide:
        Is this data publicly available (website, public API)?
          → YES: PUBLIC
          → NO: ↓
        
        Does this data belong to a specific customer or contain PII?
          → YES: Is it highly sensitive (SSN, financial, credentials, health)?
                 → YES: RESTRICTED
                 → NO: CONFIDENTIAL
          → NO: INTERNAL
    
    Example:
        >>> from security_log_fields import DataSensitivityLevel
        >>> 
        >>> # Product catalog data (anyone can see)
        >>> data_sensitivity_level = DataSensitivityLevel.PUBLIC
        >>> 
        >>> # Internal dashboard metrics (employees only)
        >>> data_sensitivity_level = DataSensitivityLevel.INTERNAL
        >>> 
        >>> # Customer agreement records (customer data)
        >>> data_sensitivity_level = DataSensitivityLevel.CONFIDENTIAL
        >>> 
        >>> # SSN, bank accounts, API keys, passwords
        >>> data_sensitivity_level = DataSensitivityLevel.RESTRICTED
    """
    
    PUBLIC = "sensitivity.level.public"
    """
    PUBLIC - Data that can be publicly shared.
    
    Use for data that is intentionally public or has no sensitivity concerns.
    
    Examples: Product catalogs, marketing content, public APIs, help docs
    """
    
    INTERNAL = "sensitivity.level.internal"
    """
    INTERNAL - Non-public internal business data, not customer-specific.
    
    Use for data that is internal to the organization but doesn't contain
    customer information or sensitive business secrets.
    
    Examples: Internal reports, aggregated metrics, config settings, team directories
    """
    
    CONFIDENTIAL = "sensitivity.level.confidential"
    """
    CONFIDENTIAL - Customer/business data that shouldn't leak.
    
    Use for data that belongs to specific customers or contains
    business-sensitive information that could cause harm if exposed.
    
    Examples: Customer records, agreements, contacts (name, email, phone), pricing
    """
    
    RESTRICTED = "sensitivity.level.restricted"
    """
    RESTRICTED - Highly sensitive data requiring maximum protection.
    
    Use for PII, credentials, financial data, or anything that could cause
    significant harm to individuals or the business if exposed.
    
    Examples: SSN, bank accounts, passwords, API keys, health/HIPAA data
    """


class EndpointSensitivity:
    """
    Endpoint sensitivity levels for classifying API endpoint sensitivity.
    
    Use these levels to indicate the sensitivity of the API endpoint being accessed.
    This should reflect the MOST sensitive data the endpoint can return/modify.
    
    Example:
        >>> from security_log_fields import EndpointSensitivity
        >>> 
        >>> # Public API endpoint
        >>> endpoint_sensitivity = EndpointSensitivity.PUBLIC
        >>> 
        >>> # Customer data endpoint  
        >>> endpoint_sensitivity = EndpointSensitivity.CONFIDENTIAL
        >>> 
        >>> # Authentication/credential endpoint
        >>> endpoint_sensitivity = EndpointSensitivity.RESTRICTED
    """
    
    PUBLIC = "sensitivity.level.public"
    """PUBLIC - Publicly accessible endpoint. Examples: Public APIs, marketing pages"""
    
    INTERNAL = "sensitivity.level.internal"
    """INTERNAL - Internal-only endpoint, non-customer data. Examples: Admin dashboards, configs"""
    
    CONFIDENTIAL = "sensitivity.level.confidential"
    """CONFIDENTIAL - Customer data or business-sensitive endpoint. Examples: Customer records"""
    
    RESTRICTED = "sensitivity.level.restricted"
    """RESTRICTED - Highly sensitive endpoint (PII, credentials). Examples: Auth, payments"""


class UserRole:
    """
    User roles for classifying the role of the user.
    
    Example:
        >>> from security_log_fields import UserRole
        >>> 
        >>> # Admin user
        >>> user_role = UserRole.ADMIN  # "role.classification.admin"
    """
    ADMIN = "role.classification.admin"
    """Admin role. Example: "role.classification.admin" """
    
    SALES_REP = "role.classification.sales_rep"
    """Sales representative. Example: "role.classification.sales_rep" """
    
    CUSTOMER_SUPPORT = "role.classification.customer_support"
    """Customer support. Example: "role.classification.customer_support" """
    
    PARTNER_ADMIN = "role.classification.partner_admin"
    """Partner admin. Example: "role.classification.partner_admin" """
    
    CUSTOMER_USER = "role.classification.customer_user"
    """Customer user. Example: "role.classification.customer_user" """


class InviteStatus:
    """
    Invite status values for user invitation events.
    
    Example:
        >>> from security_log_fields import InviteStatus
        >>> 
        >>> # Invitation sent
        >>> invite_status = InviteStatus.SENT  # "sent"
    """
    SENT = "sent"
    """Invitation sent. Example: "sent" """
    
    ACCEPTED = "accepted"
    """Invitation accepted. Example: "accepted" """
    
    REVOKED = "revoked"
    """Invitation revoked. Example: "revoked" """
    
    EXPIRED = "expired"
    """Invitation expired. Example: "expired" """


# Validation lists for standardized values
VALID_EVENT_TYPES = [
    EventType.LOGIN_ATTEMPT,
    EventType.USER_LOGOUT,
    EventType.MFA_CHALLENGE,
    EventType.PERMISSION_CHANGE,
    EventType.USER_STATUS_CHANGE,
    EventType.IMPERSONATION_EVENT,
    EventType.USER_INVITE_EVENT,
    EventType.API_REQUEST_PROCESSED,
    EventType.RECORD_ACCESS,
    EventType.MFA_STATUS_CHANGE,
    EventType.PASSWORD_CHANGE_RESET,
    EventType.API_KEY_LIFECYCLE,
    EventType.AUTH_MECHANISM_MODIFICATION
]
