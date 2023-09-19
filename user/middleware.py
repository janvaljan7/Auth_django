# from django.contrib.auth import get_user
# from django.contrib.auth.models import AnonymousUser
# from rest_framework.authtoken.models import Token

# class TokenAuthenticationMiddleware:
#     def __init__(self, get_response):
#         self.get_response = get_response

#     def __call__(self, request):
#         user = get_user(request)
#         if not user.is_authenticated:
#             try:
#                 token = request.META['AUTHORIZATION'].split(' ')[1]
#                 user = Token.objects.get(key=token).user
#             except (Token.DoesNotExist, KeyError, IndexError):
#                 user = AnonymousUser()
#         request.user = user
#         return self.get_response(request)