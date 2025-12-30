from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
from accounts.models import User

# Create your models here.

class APIKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)
    key_encrypted = models.TextField()
    revoked = models.BooleanField(default=False)
    permissions = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_key(self, raw_key):
        f = Fernet(settings.ENCRYPTION_KEY)
        self.key_encrypted = f.encrypt(raw_key.encode()).decode()

    def get_key(self):
        f = Fernet(settings.ENCRYPTION_KEY)
        return f.decrypt(self.key_encrypted.encode()).decode()

