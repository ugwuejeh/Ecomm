from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.

class Registration(AbstractUser):
    # profile_picture = models.ImageField(upload_to='profile')
    is_emailverified = models.BooleanField(default=False)
    otp = models.CharField(max_length=6)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    email = models.EmailField(max_length=254, blank=False, unique=True)

    is_vendor = models.BooleanField(default=False)
    vendor_application_status = models.CharField(max_length=20, choices=[('pending', 'Pending'), 
                                                                         ('approved', 'Approved')], 
                                                                         default='pending')
    
    # New fields for vendor application
    business_name = models.CharField(max_length=100)
    location = models.CharField(max_length=100)
    registration_no = models.CharField(max_length=50)
    registering_body = models.CharField(max_length=100)
    business_description = models.TextField()
    website_url = models.URLField(blank=True)  # website is optional

    def __str__(self):
        return self.email
    

    def save(self, *args, **kwargs):
        if self.vendor_application_status == 'approved' and not self.is_vendor:
            self.is_vendor = True
        super().save(*args, **kwargs)
    

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

