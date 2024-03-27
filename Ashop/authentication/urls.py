from django.urls import path
from .views import Signup, Verify, Register, UserAccount, VendorApply, Home, Login, Logout, VendorPage, ReverifyOtp, ForgotPassword, PasswordReset

# user/
urlpatterns = [
    path('', Signup.as_view(), name='signup'),
    path('verify/', Verify.as_view(), name='verifyit'),
    path('reverify/', ReverifyOtp.as_view(), name='reverifyit'),
    path('register/', Register.as_view(), name='registerit'),
    path('account/', UserAccount.as_view(), name='account'),
    path('apply/', VendorApply.as_view(), name='apply'),
    path('vendor/', VendorPage.as_view(), name='vendor'),
    path('home/', Home.as_view(), name='home'),
    path('login/', Login.as_view(), name='login'),
    path('logout/', Logout, name='logout'),
    path('forgot/', ForgotPassword.as_view(), name='forgot-password'),
    path('reset/<str:uidb64>/<str:token>/', PasswordReset.as_view(), name='reset-password'),    
]
