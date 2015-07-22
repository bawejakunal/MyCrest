from django.contrib import admin

# Register your models here.
from .models import *

admin.site.register(User)
admin.site.register(FileDB)
admin.site.register(Recipient)
admin.site.register(FileShare)