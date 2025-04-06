from django.db import models

# Create your models here.


class AgenteTest(models.Model):
    id = models.CharField(max_length=10, primary_key=True)
    name = models.CharField(max_length=250)
    ip = models.CharField(max_length=50)
    status = models.CharField(max_length=50)
    passed_policies = models.IntegerField(default=0)
    failed_policies = models.IntegerField(default=0)
    na_policies = models.IntegerField()
    last_scan = models.DateTimeField(null=True, blank=True)
    policy_name = models.CharField(max_length=250, null=True, blank=True)

    def __str__(self):
        return self.name
