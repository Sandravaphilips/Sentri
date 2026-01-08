import uuid

from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
from accounts.models import User


# Create your models here.

class APIKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(
        max_length=100,
        help_text="Human-readable name to identify this key (e.g. 'CI pipeline')."
    )

    key_hash = models.CharField(
        max_length=64,
        unique=True,
        help_text="Hash of the API key. Raw key is never stored."
    )
    scopes = models.JSONField(
        default=list,
        help_text="List of permitted scopes for this key."
    )

    is_revoked = models.BooleanField(
        default=False,
        help_text="Indicates whether this key has been revoked."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.user.email})"
