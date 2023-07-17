from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Q
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.conf import settings

from .models import CustomUser
from .forms import RegistrationForm, UpdateForm, SearchForm, LoginForm, ChangePasswordForm
from .decorators import check_authentication, is_user_not_owner, user_role_required, recaptcha_required

@login_required
@check_authentication
@user_role_required(['superadmin', 'admin'])
def display(request):
    search_form = SearchForm(request.GET)
    users = CustomUser.objects.exclude(id=request.user.id)
    
    if 'search' in request.GET:
        if search_form.is_valid():
            keyword = search_form.cleaned_data.get('keyword')
            role_type = search_form.cleaned_data.get('role_type')
            status = search_form.cleaned_data.get('status')
            start_date = search_form.cleaned_data.get('start_date')
            end_date = search_form.cleaned_data.get('end_date')
            
            if keyword:
                users = users.filter(
                    Q(first_name__icontains=keyword) |
                    Q(last_name__icontains=keyword) |
                    Q(username__icontains=keyword) |
                    Q(email__icontains=keyword)
                )
            if role_type:
                users = users.filter(roletype=role_type)
            if status:
                users = users.filter(is_active=(status == 'active'))
            if start_date and end_date:
                users = users.filter(date_joined__range=(start_date, end_date))
    else:
        users = CustomUser.objects.exclude(id=request.user.id)[:50]

    context = {
        'users': users,
        'search_form': search_form,
    }

    return render(request, 'users/display.html', context)

@login_required
@check_authentication
@user_role_required(['superadmin', 'admin'])
@is_user_not_owner
def update(request, id, token):
    user = get_object_or_404(CustomUser, id=id, token=token)
    update_form = UpdateForm(request.POST or None, instance=user)
    if update_form.is_valid():
        update_form.save()
        messages.success(request, 'User account ({}) has been updated successfully'.format(user.email), extra_tags="success")
        return redirect(('display.users'))
    
    context = {
        'user': user,
        'update_form': update_form,
    }
    
    return render(request, 'users/update.html', context)
    
@login_required
@check_authentication
@user_role_required(['superadmin', 'admin'])
def register(request):
    if request.method == 'POST':
        registration_form = RegistrationForm(request.POST or None)
        if registration_form.is_valid():
            registration_form.save()
            messages.info(request, 'User account has been registered successfully', extra_tags="info")
            return redirect('display.users')
    else:
        registration_form = RegistrationForm()

    context = { 'registration_form': registration_form }
    return render(request, 'users/register.html', context)

@login_required
@check_authentication
@user_role_required(['superadmin', 'admin'])
@is_user_not_owner
def deactivate(request, id, token):
    user = get_object_or_404(CustomUser, id=id, token=token)
    if request.method == 'POST':
        user.is_active = False
        user.save()
        messages.info(request, 'User account ({}) has been deactivated'.format(user.email), extra_tags="info")
        return redirect('display.users')
    else:
        return HttpResponseForbidden("Invalid request")
    
@login_required
@check_authentication
@user_role_required(['superadmin'])
@is_user_not_owner
def delete_user(request, id, token):
    user = get_object_or_404(CustomUser, id=id, token=token)
    if request.method == 'POST':
        user.delete()
        messages.info(request, 'User account ({}) has been deleted'.format(user.email), extra_tags="info")
        return redirect('display.users')
    else:
        return HttpResponseForbidden("Invalid request")

@recaptcha_required(redirect_url='login.users')
def login_user(request):
    if request.method == 'POST':
        login_form = LoginForm(request.POST)
        if login_form.is_valid():
            username = login_form.cleaned_data['username']
            password = login_form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('display.dashboard')
            else:
                login_form.add_error(None, 'Wrong Credentials')
    else:
        login_form = LoginForm()

    context = {
        'login_form': login_form,
        'recaptcha_site_key': settings.RECAPTCHA_PUBLIC_KEY
    }
    return render(request, 'users/login.html', context)

@login_required
def change_password(request, id, token):
    if request.user.id == id and request.user.token == token:
        if request.method == 'POST':
            change_password_form = ChangePasswordForm(request.user, request.POST)
            if change_password_form.is_valid():
                user = change_password_form.save()
                update_session_auth_hash(request, user)  # Important to update the session
                messages.success(request, 'Your password has been changed successfully', extra_tags="success")
                return redirect('change_password.users', id=id, token=token)
        else:
            change_password_form = ChangePasswordForm(request.user)

        context = {
            'change_password_form': change_password_form,
        }
        return render(request, 'users/change_password.html', context)  

def logout_user(request, id, token):
    if request.user.id == id and request.user.token == token:
        logout(request)
        return redirect('login.users')
    else:
        return HttpResponseForbidden("Invalid request")