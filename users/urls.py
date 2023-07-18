# from django.urls import include, path
# from rest_framework.routers import DefaultRouter

# from django.urls import path
# from .views import PrivilegedUserViewSet, LoginView, LogoutView

# router = DefaultRouter()
# router.register('users', PrivilegedUserViewSet, basename='users')

# urlpatterns = [
#     path('', PrivilegedUserViewSet.as_view({'get': 'list'}), name='user.list'),
#     path('<int:id>/', PrivilegedUserViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='user.detail'),
#     path('register/', PrivilegedUserViewSet.as_view({'post': 'create'}), name='user.register'),
#     path('login/', LoginView.as_view(), name='user.login'),
#     path('logout/', LogoutView.as_view(), name='user.logout'),
# ]

from rest_framework.routers import DefaultRouter

from django.urls import path
from .views import PrivilegedUserViewSet, LoginView, LogoutView

router = DefaultRouter()
router.register('users', PrivilegedUserViewSet, basename='users')

urlpatterns = [
    *router.urls,
    path('login/', LoginView.as_view(), name='user.login'),
    path('logout/', LogoutView.as_view(), name='user.logout'),
]