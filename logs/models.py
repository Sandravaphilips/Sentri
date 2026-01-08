from django.conf import settings
from django.db import models
from accounts.models import User
from apikeys.models import APIKey


# Create your models here.

class AuditLog(models.Model):
    ACTION_CHOICES = [
        ("signup_success", "Signup success"),
        ("login_success", "Login success"),
        ("account_locked", "Account locked"),
        ("account_unlocked", "Account unlocked"),
        ("account_compromised", "Account compromised"),
        ("compromise_cleared", "Compromise cleared"),
        ("api_key_created", "API key created"),
        ("api_key_used", "API key used"),
        ("api_key_denied", "API key denied"),
        ("api_key_revoked", "API key revoked"),
        ("all_api_keys_revoked", "All API keys revoked"),
        ("api_key_rate_limited", "API key rate limited"),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
    )

    api_key_id = models.UUIDField(null=True, blank=True)

    action = models.CharField(max_length=50, choices=ACTION_CHOICES)

    path = models.CharField(max_length=255)
    method = models.CharField(max_length=10)
    status_code = models.PositiveSmallIntegerField()

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)

    metadata = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} ({self.created_at})"
