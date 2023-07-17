from rest_framework import serializers
from .models import CustomUser

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['email', 'username', 'first_name', 'last_name', 'roletype', 'is_active', 'date_joined']
        read_only_fields = ['token', 'roletype', 'is_staff', 'date_joined']

class SuperUserAdminSerializer(UserSerializer):
    class Meta(UserSerializer.Meta):
        fields = ['image', 'email', 'username', 'first_name', 'last_name', 'roletype', 'is_active', 'date_joined']
        # read_only_fields = ['token', 'roletype', 'is_staff', 'date_joined']
        
        
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})
    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'first_name', 'last_name', 'roletype', 'password')

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = CustomUser.objects.create_user(password=password, **validated_data)
        return user