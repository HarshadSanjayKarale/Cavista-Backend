import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration"""
    
    SECRET_KEY = os.getenv('SECRET_KEY', 'cavista-hackathon-super-secret-key-2026')
    DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'
    
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/cavista_hackathon')
    
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'cavista-jwt-super-secret-2026')
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))
    
    API_VERSION = os.getenv('API_VERSION', '1.0.0')
    API_TITLE = os.getenv('API_TITLE', 'Cavista Hackathon 2026 API')
    
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/api/wearable/auth/google/callback')
    FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')
    
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False  
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_SECRET = os.getenv('SESSION_SECRET', 'cavista-session-secret-2026')
    
    # Server Configuration
    PORT = int(os.getenv('PORT', 5000))
    
    @staticmethod
    def validate_google_config():
        """Validate that Google OAuth credentials are configured"""
        if not Config.GOOGLE_CLIENT_ID or not Config.GOOGLE_CLIENT_SECRET:
            print("\n" + "="*60)
            print("WARNING: Google OAuth credentials not configured!")
            print("="*60)
            print("Please set the following in your .env file:")
            print("- GOOGLE_CLIENT_ID")
            print("- GOOGLE_CLIENT_SECRET")
            print("- REDIRECT_URI")
            print("="*60 + "\n")
            return False
        return True