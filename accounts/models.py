from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


# Create your models here.

class User(AbstractUser):
    email = models.EmailField(unique=True)
    is_email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)

    is_mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=64, blank=True, null=True)

    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)

    last_login_at = models.DateTimeField(null=True, blank=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    last_login_user_agent = models.TextField(max_length=255, blank=True)

    is_compromised = models.BooleanField(default=False)
    compromise_reason = models.CharField(max_length=255, blank=True)
    compromised_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def is_account_locked(self):
        return (
                self.account_locked_until is not None
                and self.account_locked_until > timezone.now()
        )

    def lock_remaining_seconds(self):
        if not self.is_account_locked():
            return 0

        return int(
            (self.account_locked_until - timezone.now()).total_seconds()
        )

    def __str__(self):
        return self.username or self.email
