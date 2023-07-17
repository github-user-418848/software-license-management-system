from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from .serializers import UserSerializer, SuperUserAdminSerializer, UserRegistrationSerializer
from .models import CustomUser

class UserViewSet(ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  # Add appropriate permissions as needed

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        token = self.kwargs.get('token')  # Get the token from the URL parameter
        user = get_object_or_404(queryset, token=token)  # Retrieve the user by token
        
        if self.request.user.token != user.token:
            return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
        
        if self.request.user.roletype not in ['superadmin', 'admin']:
            self.check_object_permissions(self.request, user)  # Check object-level permissions for non-admin users
        return user

    def get_serializer_class(self):
        if self.request.user.roletype == 'superadmin':
            return SuperUserAdminSerializer  # Serializer for admin users
        return UserSerializer  # Default serializer for other users

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
    
    def register(self, request, *args, **kwargs):
        if self.request.user.roletype not in ['superadmin', 'admin']:
            return Response(status=status.HTTP_403_FORBIDDEN)
            
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')  # Get the username from the request data
        password = request.data.get('password')  # Get the password from the request data
        content = request.data.get('content')  # Get the content field from the request data
        
        # Validate the username, password, and content fields
        if not username or not password or not content:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Authenticate the user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            serializer = UserSerializer(user)  # Serialize the user object
            if user.id != request.user.id and user.token != request.user.token:
                return Response({'error': 'Access denied'}, status=status.HTTP_403_FORBIDDEN)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    def post(self, request):
        logout(request)
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
        update_session_auth_hash(request, user)

        return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)