from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.authentication import SessionAuthentication, TokenAuthentication
from rest_framework.authtoken.models import Token
from django.shortcuts import get_object_or_404
from django.conf import settings
import requests

from .serializers import UserSerializer, SuperUserAdminSerializer, UserRegistrationSerializer
from .models import CustomUser
from .permissions import UserRoleRequiredPermission, CheckOwnerPermission

class PrivilegedUserViewSet(ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated, UserRoleRequiredPermission]

    def get_serializer_class(self):
        if self.request.user.roletype == 'superadmin':
            return SuperUserAdminSerializer  # Serializer for admin users
        return UserSerializer  # Default serializer for other users
    
    def create(self, request, *args, **kwargs):
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        user.set_password(request.data['password'])
        user.save()
        token = Token.objects.create(user=user)

        response_data = {
            'user': serializer.data,
            'token': token.key
        }
        
        return Response(response_data, status=status.HTTP_201_CREATED)
    
    def get(self, request, *args, **kwargs):
        instance = self.get_object()

        if request.user != instance:
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response({'error: Access Denied'}, status=status.HTTP_403_FORBIDDEN)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()

        if request.user == instance:
            serializer = self.get_serializer(instance)
            return Response(serializer.data)
        else:
            return Response({'error: Access Denied'}, status=status.HTTP_403_FORBIDDEN)

    def update(self, request, *args, **kwargs):
        if self.request.user.roletype not in ['superadmin', 'admin']:
            request.data.pop('password', None)
        
        return super().update(request, *args, **kwargs)
    
    def destroy(self, request, *args, **kwargs):
        if self.request.user.roletype != 'superadmin':
            return Response(status=status.HTTP_403_FORBIDDEN)
            
        user = self.get_object()
        self.perform_destroy(user)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, instance):
        instance.delete()

    def deactivate(self, request, *args, **kwargs):
        if user.id != request.user.id and user.token != request.user.token:
            return Response({'error: Access Denied'}, status=status.HTTP_403_FORBIDDEN)
        
        user = self.get_object()
        user.is_active = False
        user.save()
        return Response({'message': 'User deactivated successfully'}, status=status.HTTP_200_OK)
    
class LoginView(APIView):
    
    def post(self, request):
        captcha_response = request.data['g-recaptcha-response']
        is_valid_captcha = self.verify_recaptcha(captcha_response)

        if not is_valid_captcha:
            return Response({'detail': 'Invalid reCAPTCHA'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = get_object_or_404(CustomUser, username=request.data['username'])
        if not user.check_password(request.data['password']):
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        
        token, created = Token.objects.get_or_create(user=user)
        serializer = UserSerializer(instance=user)
        return Response({'token': token.key, 'user': serializer.data})
    
    @staticmethod
    def verify_recaptcha(response):
        url = 'https://www.google.com/recaptcha/api/siteverify'
        data = {
            'secret': settings.RECAPTCHA_PRIVATE_KEY,
            'response': response,
        }
        response = requests.post(url, data=data)
        result = response.json()

        if 'success' in result and result['success']:
            return True

        return False
    
class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user_token = Token.objects.get(user=request.user)
        user_token.delete()
        return Response(status=status.HTTP_200_OK)
    
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]  # Add appropriate permissions as needed

    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        if user.id != request.user.id and user.token != request.user.token:
            return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        if not user.check_password(current_password):
            return Response({'error': 'Incorrect current password'}, status=status.HTTP_400_BAD_REQUEST)
        
        user.set_password(new_password)
        user.save()

        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)