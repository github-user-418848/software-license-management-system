from django.urls import path
from .views import display, login_user, register, update, deactivate, logout_user, delete_user

urlpatterns = [
    path('', display, name='display.users'),
    path('login/', login_user, name='login.users'),
    path('register/', register, name='register.users'),
    path('<int:id>/<str:token>/', update, name='update.users'),
    path('deactivate/<int:id>/<str:token>/', deactivate, name='deactivate.users'),
    path('delete/<int:id>/<str:token>/', delete_user, name='delete.users'),
    path('logout/<int:id>/<str:token>/', logout_user, name='logout.users'),
]