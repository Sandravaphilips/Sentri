from django.db import models
from accounts.models import User
from apikeys.models import APIKey

# Create your models here.

class APILog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    api_key = models.ForeignKey(APIKey, on_delete=models.SET_NULL, null=True)
    endpoint = models.CharField(max_length=255)
    ip_address = models.GenericIPAddressField()
    method = models.CharField(max_length=10)
    status_code = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
