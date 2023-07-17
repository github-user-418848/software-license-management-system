from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import UserViewSet, LoginView, LogoutView, ChangePasswordView

router = DefaultRouter()
router.register('users', UserViewSet, basename='users')

urlpatterns = [
    path('', include(router.urls)),
    path('users/<str:token>/', UserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='user.detail'),
    path('register/', UserViewSet.as_view({'post': 'register'}), name='user.register'),
    path('login/', LoginView.as_view(), name='user.login'),
    path('logout/', LogoutView.as_view(), name='user.logout'),
    path('change-password/', ChangePasswordView.as_view(), name='user.change_password'),
]