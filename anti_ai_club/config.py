import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///anti_ai_club.db'  # or use another database URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GOOGLE_CLIENT_ID = ''
    GOOGLE_CLIENT_SECRET = ''
