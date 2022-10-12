#########################################################################
#
# Copyright (C) 2016 OSGeo
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
#########################################################################
import re
import ipaddress

from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied


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

def is_ipaddress_in_whitelist(visitor_ip, whitelist):
    # Chech if an IP is in the whitelisted IP ranges
    in_whitelist = True
    if not visitor_ip:
        in_whitelist = False
    if visitor_ip and whitelist and len(whitelist) > 0:
        visitor_ipaddress = ipaddress.ip_address(visitor_ip)
        for wip in whitelist:
            try:
                if visitor_ipaddress not in ipaddress.ip_network(wip):
                    in_whitelist = False
                    break
            except Exception:
                in_whitelist = False
    return in_whitelist


# This backend only raises a permission deined id admin access is forbidden
# It delegates to downstream backends otherwise
class AdminRestrictedAccessBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        user = super().authenticate(request, username, password, **kwargs)
        if request:
            whitelist = getattr(settings, 'ADMIN_IP_WHITELIST', [])
            if user and user.is_superuser and len(whitelist) > 0:
                visitor_ip = visitor_ip_address(request)
                if not is_ipaddress_in_whitelist(visitor_ip, whitelist):
                    raise PermissionDenied

