import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///anti_ai_club.db'  # or use another database URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GOOGLE_CLIENT_ID = '441270780672-iki68oeejo8ps8tc13peo90fu8na5540.apps.googleusercontent.com'
    GOOGLE_CLIENT_SECRET = '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'
