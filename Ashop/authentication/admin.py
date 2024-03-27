from django.contrib import admin
from .models import Registration

# Register your models here.

@admin.register(Registration)
class Useradmin(admin.ModelAdmin):
    list_display = ('email', 'username', 'otp', 'is_emailverified', 'first_name', 'last_name', 'is_vendor', 'otp_created_at')