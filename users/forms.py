from django import forms
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.forms import PasswordChangeForm
from .models import CustomUser
import re

class CommonCleanMixin:
    def clean_email(self):
        email = self.cleaned_data.get('email')
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

        if not re.match(pattern, email):
            raise forms.ValidationError("Enter a valid email address.")

        return email

    def clean_username(self):
        username = self.cleaned_data.get('username')
        pattern = r'^[a-zA-Z0-9_]+$'

        if not re.match(pattern, username):
            raise forms.ValidationError("Username can only contain uppercase letters, lowercase letters, numbers and '_'")

        return username

    def clean_first_name(self):
        first_name = self.cleaned_data.get('first_name')

        if not first_name.replace(' ', '').isalpha():
            raise forms.ValidationError("First name can only contain letters and spaces")

        return first_name

    def clean_last_name(self):
        last_name = self.cleaned_data.get('last_name')

        if not last_name.replace(' ', '').isalpha():
            raise forms.ValidationError("Last name can only contain letters and spaces")

        return last_name
    
class LoginForm(forms.Form):
    username = forms.CharField(label='Username')
    password = forms.CharField(label='Password', widget=forms.PasswordInput)

class RegistrationForm(forms.ModelForm, CommonCleanMixin):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput)
    
    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'first_name', 'last_name', 'roletype', 'password1', 'password2')
    
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")

        return cleaned_data
        
    def save(self, commit=True):
        user = super(RegistrationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password2"])

        if commit:
            user.save()

        return user
    
class UpdateForm(forms.ModelForm, CommonCleanMixin):
    class Meta:
        model = CustomUser
        fields = ('email', 'username', 'first_name', 'last_name', 'roletype', 'is_active', 'is_staff')

class SearchForm(forms.Form):
    ROLETYPES = (
        ('', _('All')),
        ('superadmin', _('Super Admin')),
        ('admin', _('Admin')),
        ('general', _('General User')),
    )
    STATUSES = (
        ('', _('All')),
        ('active', _('Active')),
        ('inactive', _('Inactive')),
    )
    keyword = forms.CharField(label=_('Search'), max_length=50, required=False)
    role_type = forms.ChoiceField(label="Role Type", choices=ROLETYPES, required=False)
    status = forms.ChoiceField(choices=STATUSES, required=False)
    start_date = forms.DateField(
        label=_('Date joined (start)'),
        widget=forms.DateInput(attrs={'type': 'date'}),
        required=False,
    )
    end_date = forms.DateField(
        label=_('Date joined (end)'),
        widget=forms.DateInput(attrs={'type': 'date'}),
        required=False,
    )
    
    def clean_keyword(self):
        keyword = self.cleaned_data.get('keyword')
        pattern = r'^[a-zA-Z0-9@_.]+$'

        if keyword and not re.match(pattern, keyword):
            raise forms.ValidationError("Keyword can only contain uppercase letters, lowercase letters, numbers, '@', '_', and '.'")

        return keyword
    
    def clean(self):
        cleaned_data = super().clean()
        date_joined_start = cleaned_data.get('date_joined_start')
        date_joined_end = cleaned_data.get('date_joined_end')

        if date_joined_start and date_joined_end and date_joined_start > date_joined_end:
            raise forms.ValidationError("Start date cannot be later than end date.")
            
        return cleaned_data

class ChangePasswordForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['old_password'].widget = forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Current Password'})
        self.fields['new_password1'].widget = forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'New Password'})
        self.fields['new_password2'].widget = forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm New Password'})
