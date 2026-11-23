import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone


class Item(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160, blank=True)
    paused = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)
    revision = models.PositiveIntegerField(default=1)
    current = models.ForeignKey('Blob', null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    previous = models.ForeignKey('Blob', null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    updated = models.DateTimeField(default=timezone.now)

    @property
    def title(self):
        return self.name or (self.current.filename if self.current else '文件')


class Blob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    item = models.ForeignKey(Item, on_delete=models.CASCADE, related_name='blobs')
    filename = models.CharField(max_length=240)
    size = models.PositiveBigIntegerField()
    sha256 = models.CharField(max_length=64)
    created = models.DateTimeField(default=timezone.now)
    removed = models.BooleanField(default=False)


class Upload(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    key = models.UUIDField(unique=True)
    request_hash = models.CharField(max_length=64)
    name = models.CharField(max_length=160, blank=True)
    filename = models.CharField(max_length=240)
    size = models.PositiveBigIntegerField()
    received = models.PositiveBigIntegerField(default=0)
    fingerprint = models.CharField(max_length=64)
    target = models.ForeignKey(Item, null=True, on_delete=models.CASCADE)
    expected_revision = models.PositiveIntegerField(null=True)
    status = models.CharField(max_length=16, default='uploading')
    result = models.ForeignKey(Item, null=True, on_delete=models.SET_NULL, related_name='+')
    touched = models.DateTimeField(default=timezone.now)


class Budget(models.Model):
    key = models.CharField(max_length=80, primary_key=True)
    count = models.PositiveIntegerField(default=0)
    until = models.DateTimeField()


class Operation(models.Model):
    key = models.UUIDField(primary_key=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    request_hash = models.CharField(max_length=64)
    result = models.JSONField(default=dict)
    created = models.DateTimeField(default=timezone.now)


class Event(models.Model):
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=40)
    item_ref = models.CharField(max_length=36, blank=True)
    created = models.DateTimeField(default=timezone.now)
