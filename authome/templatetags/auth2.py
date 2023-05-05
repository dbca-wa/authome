from django import template
from django.conf import settings

from authome import models

register = template.Library()

@register.simple_tag(takes_context=True)
def can_access(context,url):
    try:
        request = context['request']
        return models.can_access(request.user.email,settings.AUTH2_DOMAIN,url)
    except Exception as e:
        return False

