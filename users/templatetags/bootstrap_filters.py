from django import template
from django.utils.safestring import SafeString

register = template.Library()

@register.filter
def add_bootstrap_class(field, css_class):
    """Adds the specified CSS class to the form field and includes validation error codes if present."""
    css_classes = field.field.widget.attrs.get('class', '')
    css_classes += f' {css_class}'
    
    if field.errors:
        css_classes += ' is-invalid'
        error_messages = ''
        for error in field.errors:
            error_messages += f'<div class="invalid-feedback small">{error}</div>'
        
        return SafeString(field.as_widget(attrs={"class": css_classes})) + SafeString(error_messages)
    
    return field.as_widget(attrs={"class": css_classes})

register.filter('add_bootstrap_class', add_bootstrap_class)