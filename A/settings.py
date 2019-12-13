"""
Django settings for A project.

Generated by 'django-admin startproject' using Django 2.2.3.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
from googlemaps import Client
import pytz

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'u*0dpb92__ipl20f%3z==m82k2e&gq#*n*fc&fidxptbu_p+pq'

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

# Maaz Twilio account credentials
SENDER_PHONE_NUMBER = '+12015080329'
TWILIO_ACCOUNT_SID = 'AC9ba1aaf65554a3f2b85d59f00ae4ad0a'
TWILIO_AUTH_TOKEN = '33545ed3be08f4d14a4a21cdb56d4050'

# Sohaib Twilio account credentials
# TWILIO_ACCOUNT_SID = 'ACc2d21586f29d9728eb8be6b7f7cbab17'
# TWILIO_AUTH_TOKEN = '6b978d120ab33f30ce16ee4e275df2f9'
# SENDER_PHONE_NUMBER = '+12068097984'

# Google Maps Api Key.
GOOGLE_API_KEY = 'AIzaSyCxh6jiboDAWzR7c_373KDStrtj2W4Sgg4'
gmaps = Client(key=GOOGLE_API_KEY)

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
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
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
SERVER_EMAIL = 'maazsabahuddin@gmail.com'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'maazsabahuddin@gmail.com'
EMAIL_HOST_PASSWORD = 'tlypbqtxmuxjeysy'
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'

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
EMAIL_VERIFICATION = True

# Phone Verification
PHONE_VERIFICATION = True

# FIXED_FARE_PRICE = 50
# KILOMETER_FARE_PRICE = 8.8
KILOMETER_FARE = True
FIXED_FARE = False

# Payment through Foree, Easypaisa and more.
ONLINE_PAYMENT = True
ONLINE_PAYMENT_FEE = False

DISTANCE_KILOMETRE_LIMIT = 2.0

# Each stop wait time in minutes.
STOP_WAIT_TIME = 1
