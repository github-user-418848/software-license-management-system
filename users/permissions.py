from rest_framework.permissions import BasePermission

class UserRoleRequiredPermission(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.roletype in ['superadmin', 'admin']

class CheckOwnerPermission(BasePermission):
    def has_permission(self, request, view):
        id = view.kwargs.get('id')
        token = view.kwargs.get('token')
        user = request.user
        return user.id != id and user.token != token
