class AuditEvent:
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_COMPROMISED = "account_compromised"

    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_USED = "api_key_used"
    APi_KEY_DENIED = "api_key_denied"
    API_KEY_RATE_LIMITED = "api_key_rate_limited"
