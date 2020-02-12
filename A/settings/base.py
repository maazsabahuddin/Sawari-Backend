"""
Django settings for A project.

Generated by 'django-admin startproject' using Django 2.2.3.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

import os
import re
import googlemaps
import pytz

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True


ALLOWED_HOSTS = ['*']

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'User',
    'Reservation',
    'Payment',
    'RideSchedule',
    'rest_framework',
    'rest_framework.authtoken',
    'django_twilio',
]

# if use file extraction method.
# retrieve external file data
# AWS server absolute path.
# file_url = '/home/ec2-user/SAWARI_backend/A/secret_keys.txt'
file_url = 'I:/Work/MyGithub/secret_keys.txt'
retrieve_keys_of_list = []
try:
    with open(file_url, 'r') as f:
        for line in f:
            inner_list = [elt.strip() for elt in line.split(',')]
            inner_list = list(filter(None, inner_list))
            if not inner_list:
                continue
            retrieve_keys_of_list.append(inner_list)
except:
    print("Unable to open file secret_keys")

list_value = []
dict_keys = []
secret_keys = []

for string_list in retrieve_keys_of_list:
    list_value = string_list[0].split('=')
    for string_value in list_value:
        string_without_space = re.sub(' +', '', string_value)
        secret_keys.append(string_without_space)
    dict_keys.append({secret_keys[0]: secret_keys[1]})
    secret_keys.clear()

# Maaz Twilio account credentials
TWILIO_ACCOUNT_SID = dict_keys[0].get('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = dict_keys[1].get('TWILIO_AUTH_TOKEN')
SENDER_PHONE_NUMBER = dict_keys[2].get('SENDER_PHONE_NUMBER')

# Google Key
GOOGLE_API_KEY = dict_keys[3].get('GOOGLE_API_KEY')
gmaps = googlemaps.Client(key=GOOGLE_API_KEY)

# Django Secret Key
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = dict_keys[4].get('DJANGO_SECRET_KEY')

# if use os credentials
# Twilio Credentials
# TWILIO_ACCOUNT_SID = os.environ['TWILIO_ACCOUNT_SID']
# TWILIO_AUTH_TOKEN = os.environ['TWILIO_AUTH_TOKEN']

# Google Maps Api Key.
# GOOGLE_API_KEY = os.environ['GOOGLE_API_KEY']
# gmaps = googlemaps.Client(key=GOOGLE_API_KEY)

AUTH_USER_MODEL = "User.User"

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'A.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # 'User.context_processors.settings',
            ],
        },
    },
]

WSGI_APPLICATION = 'A.wsgi.application'


# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join('db.sqlite3'),
        # 'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


REST_FRAMEWORK = {
    # 'DEFAULT_AUTHENTICATION_CLASSES': [
    #     'rest_framework.authentication.TokenAuthentication',
    # ],
}

AUTHENTICATION_BACKENDS = (
    'CustomAuthentication.backend_authentication.CustomAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
)

# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Karachi'
local_tz = pytz.timezone(TIME_ZONE)

USE_I18N = True

USE_L10N = True

USE_TZ = True

EMAIL_USE_TLS = True
SERVER_EMAIL = dict_keys[5].get('SERVER_EMAIL')
EMAIL_HOST = dict_keys[6].get('EMAIL_HOST')
EMAIL_PORT = dict_keys[7].get('EMAIL_PORT')
EMAIL_HOST_PASSWORD = dict_keys[8].get('EMAIL_HOST_PASSWORD')
EMAIL_HOST_USER = dict_keys[9].get('EMAIL_HOST_USER')
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
EMAIL_BACKEND = dict_keys[10].get('EMAIL_BACKEND')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# STATIC FILES
STATIC_URL = '/static/'
# STATIC_ROOT = '/home/sohaibaijaz9/SAWAARI_backend/static'
STATIC_ROOT = os.path.join(BASE_DIR, "static/")

# MEDIA FILES
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

# Changes as per business requirements.
OTP_COUNTER_LIMIT = 3

# kitni der tk otp valid rhega.
OTP_VALID_TIME = 120

# Initial Counter
OTP_INITIAL_COUNTER = 1

# Country code
COUNTRY_CODE_PK = "92"

# Regex Phone Number
PHONE_NUMBER_REGEX = r"\+" + COUNTRY_CODE_PK + r"3\d{9}"

# Email REGEX
EMAIL_REGEX = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"

# Email Verification
EMAIL_VERIFICATION = False

# Phone Verification
PHONE_VERIFICATION = True

# FIXED_FARE_PRICE = 50
# KILOMETER_FARE_PRICE = 8.8

KILOMETER_FARE = False
FIXED_FARE = True

# Payment through Foree, Easypaisa and more.
ONLINE_PAYMENT = True
ONLINE_PAYMENT_FEE = False

DISTANCE_KILOMETRE_LIMIT = 2.0

# Each stop wait time in minutes.
STOP_WAIT_TIME = 1

# LOGGING = {
#     'version': 1,
#     'disable_existing_loggers': False,
#     'handlers': {
#         'file': {
#             'level': 'DEBUG',
#             'class': 'logging.FileHandler',
#             'filename': '/app.log',
#         },
#     },
#     'loggers': {
#         'django': {
#             'handlers': ['file'],
#             'level': 'DEBUG',
#             'propagate': True,
#         },
#     },
# }
