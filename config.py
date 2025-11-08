import os

class Config:
    # Secret key for session management and security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_very_secret_and_complex_key_2023'
    
    # SQLAlchemy configuration for SQLite
    SQLALCHEMY_DATABASE_URI = 'sqlite:///healthcare.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Default initial admin credentials
    DEFAULT_ADMIN_NAME = 'Super Admin'
    DEFAULT_ADMIN_EMAIL = 'admin@healthcare.com'
    DEFAULT_ADMIN_PASSWORD = 'admin123'