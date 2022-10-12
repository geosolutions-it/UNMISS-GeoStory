# -*- coding: utf-8 -*-
#########################################################################
#
# Copyright (C) 2017 OSGeo
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

# Django settings for the GeoNode project.
import os
import ast

try:
    from urllib.parse import urlparse, urlunparse
    from urllib.request import urlopen, Request
except ImportError:
    from urllib2 import urlopen, Request
    from urlparse import urlparse, urlunparse
# Load more settings from a file called local_settings.py if it exists
try:
    from UNMISS_geonode.local_settings import *
#    from geonode.local_settings import *
except ImportError:
    from geonode.settings import *

#
# General Django development settings
#
PROJECT_NAME = 'UNMISS_geonode'

# add trailing slash to site url. geoserver url will be relative to this
if not SITEURL.endswith('/'):
    SITEURL = '{}/'.format(SITEURL)

SITENAME = os.getenv("SITENAME", 'UNMISS_geonode')

ALLOWED_HOSTS = ['southsudanmaps-dev.un.org']
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTOCOL', 'https')
SESSION_COOKIE_SECURE = ast.literal_eval(os.environ.get('SESSION_COOKIE_SECURE', 'True'))
CSRF_COOKIE_SECURE = ast.literal_eval(os.environ.get('CSRF_COOKIE_SECURE', 'True'))
CSRF_COOKIE_HTTPONLY = ast.literal_eval(os.environ.get('CSRF_COOKIE_HTTPONLY', 'False'))
# CSRF_COOKIE_DOMAIN = os.environ.get('CSRF_COOKIE_DOMAIN', 'https://*.un.org')
CSRF_TRUSTED_ORIGINS = ALLOWED_HOSTS
USE_X_FORWARDED_HOST = ast.literal_eval(os.environ.get('USE_X_FORWARDED_HOST', 'True'))

# Defines the directory that contains the settings file as the LOCAL_ROOT
# It is used for relative settings elsewhere.
LOCAL_ROOT = os.path.abspath(os.path.dirname(__file__))

WSGI_APPLICATION = "{}.wsgi.application".format(PROJECT_NAME)

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = os.getenv('LANGUAGE_CODE', "en")

if PROJECT_NAME not in INSTALLED_APPS:
    INSTALLED_APPS += (PROJECT_NAME,)

# Location of url mappings
ROOT_URLCONF = os.getenv('ROOT_URLCONF', '{}.urls'.format(PROJECT_NAME))

# Additional directories which hold static files
# - Give priority to local geonode-project ones
STATICFILES_DIRS = [os.path.join(LOCAL_ROOT, "static"), ] + STATICFILES_DIRS

# Location of locale files
LOCALE_PATHS = (
    os.path.join(LOCAL_ROOT, 'locale'),
    ) + LOCALE_PATHS

TEMPLATES[0]['DIRS'].insert(0, os.path.join(LOCAL_ROOT, "templates"))
loaders = TEMPLATES[0]['OPTIONS'].get('loaders') or ['django.template.loaders.filesystem.Loader','django.template.loaders.app_directories.Loader']
# loaders.insert(0, 'apptemplates.Loader')
TEMPLATES[0]['OPTIONS']['loaders'] = loaders
TEMPLATES[0].pop('APP_DIRS', None)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d '
                      '%(thread)d %(message)s'
        },
        'simple': {
            'format': '%(message)s',
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'console': {
            'level': 'ERROR',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler',
        }
    },
    "loggers": {
        "django": {
            "handlers": ["console"], "level": "ERROR", },
        "geonode": {
            "handlers": ["console"], "level": "INFO", },
        "geoserver-restconfig.catalog": {
            "handlers": ["console"], "level": "ERROR", },
        "owslib": {
            "handlers": ["console"], "level": "ERROR", },
        "pycsw": {
            "handlers": ["console"], "level": "ERROR", },
        "celery": {
            "handlers": ["console"], "level": "DEBUG", },
        "mapstore2_adapter.plugins.serializers": {
            "handlers": ["console"], "level": "DEBUG", },
        "geonode_logstash.logstash": {
            "handlers": ["console"], "level": "DEBUG", },
    },
}

CENTRALIZED_DASHBOARD_ENABLED = ast.literal_eval(os.getenv('CENTRALIZED_DASHBOARD_ENABLED', 'False'))
if CENTRALIZED_DASHBOARD_ENABLED and USER_ANALYTICS_ENABLED and 'geonode_logstash' not in INSTALLED_APPS:
    INSTALLED_APPS += ('geonode_logstash',)

    CELERY_BEAT_SCHEDULE['dispatch_metrics'] = {
        'task': 'geonode_logstash.tasks.dispatch_metrics',
        'schedule': 3600.0,
    }

LDAP_ENABLED = ast.literal_eval(os.getenv('LDAP_ENABLED', 'False'))
if LDAP_ENABLED and 'geonode_ldap' not in INSTALLED_APPS:
    INSTALLED_APPS += ('geonode_ldap',)

# Add your specific LDAP configuration after this comment:
# https://docs.geonode.org/en/master/advanced/contrib/#configuration

# Switch off the default basemaps
for msbase in MAPSTORE_BASELAYERS:
    msbase['visibility'] = False

# Add UNMISS basemap to head and switch it on
MAPSTORE_BASELAYERS = [
    {
        "type": "tileprovider",
        "title": "UNMISS Basemap",
        "provider": "custom",
        "name": "",
        "group": "background",
        "visibility": True,
        "url": "https://pro-ags1.dfs.un.org/arcgis/rest/services/UNMISS_Custom_Basemap_CVW/MapServer/tile/{z}/{y}/{x}",
        "thumbURL": "https://unmiss.unmissions.org/sites/all/themes/unmpk/logo.png",
    }
] + MAPSTORE_BASELAYERS

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator', },
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 14, 
        }
    },
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator', },
    {'NAME': 'UNMISS_geonode.security.password_validators.UppercaseValidator', },
    {'NAME': 'UNMISS_geonode.security.password_validators.NumberValidator', 
        'OPTIONS': {
            'min_digits': 1, 
        } 
    },
    {'NAME': 'UNMISS_geonode.security.password_validators.LowercaseValidator', },
    {'NAME': 'UNMISS_geonode.security.password_validators.SpecialCharsValidator', }
]

# ADMIN_IP_WHITELIST property limits access as admin
# to only whitelisted IP addresses.
#
# Empty list means 'allow all'
#
# If you need to limit admin access to some specific IPs
# fill the list like below:
#
# ADMIN_IP_WHITELIST = ['192.168.1.158', '192.168.1.159']
ADMIN_IP_WHITELIST = [] if os.getenv('ADMIN_IP_WHITELIST') is None \
    else re.split(r' *[,|:;] *', os.getenv('ADMIN_IP_WHITELIST'))
if len(ADMIN_IP_WHITELIST) > 0:
    print("ACTIVATING ADMIN WHITELISTING")
    AUTHENTICATION_BACKENDS = ('UNMISS_geonode.security.backends.AdminRestrictedAccessBackend',) + AUTHENTICATION_BACKENDS
    MIDDLEWARE += ('UNMISS_geonode.security.middleware.AdminAllowedMiddleware',)
