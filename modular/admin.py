# blog/admin.py

from django.contrib import admin
from .models import GlobalFailedChecksHistory, AgentFailedChecksSummary

admin.site.register(GlobalFailedChecksHistory)
admin.site.register(AgentFailedChecksSummary)