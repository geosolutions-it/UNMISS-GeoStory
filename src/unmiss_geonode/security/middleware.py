import re
import ipaddress
import logging
import traceback

from django.conf import settings
from django.contrib.auth import logout, authenticate
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser

from oauth2_provider.models import AccessToken

from geonode.base.auth import (
    basic_auth_authenticate_user,
    get_token_from_auth_header
)

logger = logging.getLogger(__name__)


def visitor_ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = None
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    if ip:
        ip = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ip)[0]
    return ip


def get_token_object(token):
    try:
        access_token = AccessToken.objects.filter(token=token).first()
        if access_token and access_token.is_valid():
            return access_token
    except Exception:
        tb = traceback.format_exc()
        if tb:
            logger.debug(tb)
    return None


def get_auth_user_from_token(token):
    access_token = get_token_object(token)
    if access_token:
        return access_token.user


def token_header_authenticate_user(auth_header: str):
    token = get_token_from_auth_header(auth_header)
    return get_auth_user_from_token(token)


def extract_user_from_headers(request):
    user = AnonymousUser()
    if "HTTP_AUTHORIZATION" in request.META:
        auth_header = request.META.get("HTTP_AUTHORIZATION", request.META.get("HTTP_AUTHORIZATION2"))

        if auth_header and "Basic" in auth_header:
            user = basic_auth_authenticate_user(auth_header)
        elif auth_header and "Bearer" in auth_header:
            user = token_header_authenticate_user(auth_header)

    if "apikey" in request.GET:
        user = get_auth_user_from_token(request.GET.get('apikey'))
    return user


class AdminAllowedMiddleware(MiddlewareMixin):
    """
    Middleware that checks if admin is making requests from allowed IPs.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def process_request(self, request):
        whitelist = getattr(settings, 'ADMIN_IP_WHITELIST', [])
        if len(whitelist) > 0:
            user = None

            if request.method == 'POST':
                login_username = request.POST.get('login', None)
                login_password = request.POST.get('password', None)
                user = authenticate(username=login_username, password=login_password)
            if not user:
                user = extract_user_from_headers(request)
            if not user and getattr(request, "user", None):
                user = request.user

            if user and user.is_superuser:
                visitor_ip = visitor_ip_address(request)
                in_whitelist = False
                if visitor_ip:
                    visitor_ipaddress = ipaddress.ip_address(visitor_ip)
                    for wip in whitelist:
                        try:
                            if visitor_ipaddress in ipaddress.ip_network(wip):
                                in_whitelist = True
                                break
                        except Exception:
                            pass
                if not visitor_ip or not in_whitelist:
                    try:
                        if getattr(request, "session", None):
                            logout(request)
                        if getattr(request, "user", None):
                            request.user = AnonymousUser()
                        if "HTTP_AUTHORIZATION" in request.META:
                            del request.META["HTTP_AUTHORIZATION"]
                        if "apikey" in request.GET:
                            del request.GET["apikey"]
                    finally:
                        try:
                            from django.contrib import messages
                            from django.utils.translation import ugettext_noop as _
                            messages.warning(request, _(f"Admin access forbidden from {visitor_ip}"))
                        except Exception:
                            pass
