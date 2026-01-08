from django.db import models
from django.conf import settings


class SecurityEvent(models.Model):

    class EventType(models.TextChoices):
        SIGNUP_SUCCESS = "SIGNUP_SUCCESS", "Signup success"
        SIGNUP_FAILED = "SIGNUP_FAILED", "Signup failed"
        LOGIN_SUCCESS = "LOGIN_SUCCESS", "Login Success"
        LOGIN_FAILED = "LOGIN_FAILED", "Login Failed"
        ACCOUNT_LOCKED = "ACCOUNT_LOCKED", "Account Locked"
        ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED", "Account unLocked"

        API_KEY_CREATED = "API_KEY_CREATED", "API Key Created"
        API_KEY_CREATION_BLOCKED = "API_KEY_CREATION_BLOCKED", "API Key Creation Blocked"
        API_KEY_REVOKED = "API_KEY_REVOKED", "API Key Revoked"
        API_KEY_REVOCATION_BLOCKED = "API_KEY_REVOCATION_BLOCKED", "API Key REVOCATION Blocked"
        API_KEY_AUTH_FAILED = "API_KEY_AUTH_FAILED", "API Key Auth Failed"
        API_KEY_EXPIRED = "API_KEY_EXPIRED", "API Key Expired"

        SCOPE_VIOLATION = "SCOPE_VIOLATION", "Scope Violation"

        COMPROMISE_DETECTED = "COMPROMISE_DETECTED", "Compromise Detected"
        REMEDIATION_APPLIED = "REMEDIATION_APPLIED", "Remediation Applied"

    class Severity(models.TextChoices):
        LOW = "LOW", "Low"
        MEDIUM = "MEDIUM", "Medium"
        HIGH = "HIGH", "High"
        CRITICAL = "CRITICAL", "Critical"

    event_type = models.CharField(
        max_length=64,
        choices=EventType.choices,
    )

    severity = models.CharField(
        max_length=16,
        choices=Severity.choices,
        default=Severity.LOW,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
    )

    api_key = models.ForeignKey(
        "apikeys.APIKey",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_events",
    )

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event_type"]),
            models.Index(fields=["severity"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"{self.event_type} ({self.severity})"
