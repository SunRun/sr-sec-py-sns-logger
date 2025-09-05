# File: security_log_fields.py

class AuthProtocol:
    API_KEY = "api_key"
    OAUTH2_JWT = "oauth2_jwt"
    OAUTH2_CLIENT_SECRET = "oauth2_client_secret"
    NORMALIZED_USER_ID = "normalized_user_id"
    SAML = "saml"

class ActionType:
    # General Actions
    VIEWED = "record_viewed"
    CREATED = "record_created"
    EDITED = "record_edited"
    DELETED = "record_deleted"
    LIST_VIEWED = "list_viewed"
    EXPORTED = "exported"
    # User Status
    USER_ENABLED = "user_enabled"
    USER_DISABLED = "user_disabled"
    USER_DELETED = "user_deleted"
    # Impersonation
    IMPERSONATION_START = "impersonation_start"
    IMPERSONATION_STOP = "impersonation_stop"

class AuthorizationStatus:
    SUCCESS = "Success"
    FAILURE = "Failure"

class UserType:
    INTERNAL = "internal"
    PARTNER = "partner"
    CUSTOMER = "customer"
    API_USER = "api_user"
    SELF = "self"

class EventType:
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    MFA_CHALLENGE = "mfa_challenge"

class ChangeType:
    # MFA
    MFA_DISABLED = "mfa_disabled"
    MFA_ENABLED = "mfa_enabled"
    NEW_MFA_DEVICE = "new_mfa_device"
    # Password
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    # API Key
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    # Auth Mechanisms
    NEW_SSO_PROVIDER = "new_sso_provider"
    ENABLE_LOCAL_AUTHN = "enable_local_authN"