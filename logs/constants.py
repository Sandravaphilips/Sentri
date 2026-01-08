class AuditEvent:
    SIGNUP_SUCCESS = "signup_success"
    LOGIN_SUCCESS = "login_success"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_COMPROMISED = "account_compromised"
    COMPROMISE_CLEARED = "compromise_cleared"

    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"
    APi_KEY_DENIED = "api_key_denied"
    API_KEY_RATE_LIMITED = "api_key_rate_limited"
    ALL_API_KEYS_REVOKED = "all_api_keys_revoked"
