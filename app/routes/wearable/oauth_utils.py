"""
OAuth 2.0 utilities for Google Fit integration
"""
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import session, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()

# OAuth Configuration
GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_FIT_API = 'https://www.googleapis.com/fitness/v1/users/me'

SCOPES = ' '.join([
    'https://www.googleapis.com/auth/fitness.activity.read',
    'https://www.googleapis.com/auth/fitness.heart_rate.read',
    'https://www.googleapis.com/auth/fitness.sleep.read',
    'https://www.googleapis.com/auth/fitness.body.read',
    'https://www.googleapis.com/auth/fitness.blood_pressure.read',
    'https://www.googleapis.com/auth/fitness.oxygen_saturation.read'
])

def get_google_auth_url():
    """Generate Google OAuth authorization URL"""
    auth_url = (
        f"{GOOGLE_AUTH_URL}?"
        f"client_id={os.getenv('GOOGLE_CLIENT_ID')}&"
        f"redirect_uri={os.getenv('REDIRECT_URI')}&"
        f"response_type=code&"
        f"scope={requests.utils.quote(SCOPES)}&"
        f"access_type=offline&"
        f"prompt=consent"
    )
    return auth_url

def exchange_code_for_tokens(code):
    """Exchange authorization code for access and refresh tokens"""
    try:
        response = requests.post(GOOGLE_TOKEN_URL, data={
            'code': code,
            'client_id': os.getenv('GOOGLE_CLIENT_ID'),
            'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
            'redirect_uri': os.getenv('REDIRECT_URI'),
            'grant_type': 'authorization_code'
        })
        
        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")
        
        return response.json()
    except Exception as e:
        print(f'Token exchange error: {str(e)}')
        raise

def refresh_access_token(refresh_token):
    """Refresh an expired access token"""
    try:
        response = requests.post(GOOGLE_TOKEN_URL, data={
            'refresh_token': refresh_token,
            'client_id': os.getenv('GOOGLE_CLIENT_ID'),
            'client_secret': os.getenv('GOOGLE_CLIENT_SECRET'),
            'grant_type': 'refresh_token'
        })
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Token refresh failed: {response.text}")
    except Exception as e:
        print(f'Token refresh error: {str(e)}')
        raise

def require_google_auth(f):
    """
    Decorator to require Google Fit authentication for routes
    Automatically refreshes expired tokens
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return jsonify({
                'success': False,
                'error': 'Not authenticated with Google Fit',
                'message': 'Please authenticate first via /api/wearable/auth/google'
            }), 401
        
        # Check if token expired and refresh if needed
        if datetime.now().timestamp() * 1000 >= session.get('token_expiry', 0):
            if 'refresh_token' not in session:
                return jsonify({
                    'success': False,
                    'error': 'No refresh token available',
                    'message': 'Please re-authenticate via /api/wearable/auth/google'
                }), 401
            
            try:
                data = refresh_access_token(session['refresh_token'])
                session['access_token'] = data['access_token']
                session['token_expiry'] = datetime.now().timestamp() * 1000 + (data['expires_in'] * 1000)
                print('Access token refreshed successfully')
            except Exception as e:
                session.clear()
                return jsonify({
                    'success': False,
                    'error': 'Token refresh failed',
                    'message': str(e)
                }), 401
        
        return f(*args, **kwargs)
    return decorated_function

def get_authorized_headers():
    """Get headers with current access token for API requests"""
    return {
        'Authorization': f"Bearer {session['access_token']}",
        'Content-Type': 'application/json'
    }