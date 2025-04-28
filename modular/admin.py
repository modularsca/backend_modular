# blog/admin.py

from django.contrib import admin

from .models import AgenteTest, PolicyChecksTest

admin.site.register(AgenteTest)
admin.site.register(PolicyChecksTest)