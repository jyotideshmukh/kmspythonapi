from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import authentication, permissions
from django.contrib.auth.models import User

class Doencryption(APIView):

    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAdminUser]