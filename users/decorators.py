from django.http import HttpResponseForbidden
from django.shortcuts import redirect
from django.conf import settings
from django.contrib import messages
from functools import wraps
import requests

def check_authentication(view_func):
    def wrapper(request, *args, **kwargs):
        user = request.user
        if user.is_authenticated:
            return view_func(request, *args, **kwargs)
        else:
            return redirect('login.users')
    return wrapper

def user_role_required(roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated or request.user.roletype not in roles:
                return HttpResponseForbidden("Invalid request.")
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

def is_user_not_owner(view_func):
    def wrapper(request, *args, **kwargs):
        id = kwargs['id']
        token = kwargs['token']
        user = request.user
        if user.id != id and user.token != token:
            return view_func(request, *args, **kwargs)
        else:
            return HttpResponseForbidden("Sorry can't do that.")
    return wrapper


def recaptcha_required(redirect_url):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.method == 'POST':
                captcha_response = request.POST.get('g-recaptcha-response')
                data = {
                    'secret': settings.RECAPTCHA_PRIVATE_KEY,
                    'response': captcha_response
                }
                response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
                result = response.json()
                
                if not result['success']:
                    messages.error(request, 'Invalid CAPTCHA. Please try again.', extra_tags="warning")
                    return redirect(redirect_url)
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    
    return decorator