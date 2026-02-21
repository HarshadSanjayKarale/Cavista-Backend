import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'cavista-secret-2026')
    
    # MongoDB Config - UPDATED
    MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/cavista_hackathon')
    MONGO_CONNECT = True
    MONGO_MAX_POOL_SIZE = 10
    MONGO_MIN_POOL_SIZE = 1
    
    # JWT Config
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-2026')
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))