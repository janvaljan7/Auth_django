from django.core.cache import cache
from django.core.mail import send_mail
import random
from django.conf import settings
from .models import UserProfile

def send_otp_via_email(email):
    """Sending otp to email."""
    subject = 'No-reply, email verification'
    otp = random.randint(100000, 999999)
    # Save OTP in cache or Redis with 2 minutes expiration time
    cache.set(email, otp, timeout=120) # 120 seconds = 2 minutes
    message = f'Your verification code: {otp}'
    email_from = settings.EMAIL_HOST
    send_mail(subject, message, email_from, [email])
    user_obj = UserProfile.objects.get(email=email)
    user_obj.otp = otp
    user_obj.save()