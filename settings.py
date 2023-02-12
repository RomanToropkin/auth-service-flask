from os import environ
from datetime import timedelta

SQLALCHEMY_DATABASE_URI = environ.get("DB_URL")
SQLALCHEMY_TRACK_MODIFICATIONS = False
DEBUG = True
JWT_COOKIE_SECURE = False
JWT_TOKEN_LOCATION = ["headers", "cookies"]
JWT_SECRET_KEY = environ.get("JWT_SECRET")
JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=1)
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)