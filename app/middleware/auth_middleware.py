from functools import wraps
from flask import request, jsonify
import jwt
import os
from app.extensions import mongo

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]  # Bearer <token>
            except IndexError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid token format. Use: Bearer <token>'
                }), 401
        
        if not token:
            return jsonify({
                'success': False,
                'error': 'Token is missing'
            }), 401
        
        try:
            # Decode the token
            data = jwt.decode(
                token, 
                os.getenv('JWT_SECRET_KEY'), 
                algorithms=["HS256"]
            )
            
            # Get user from database
            user_id = data.get('user_id')
            user_type = data.get('user_type')
            
            if not user_id or not user_type:
                return jsonify({
                    'success': False,
                    'error': 'Invalid token payload'
                }), 401
            
            # Find user in appropriate collection
            if user_type == 'patient':
                current_user = mongo.db.patients.find_one({'_id': user_id})
            elif user_type == 'doctor':
                current_user = mongo.db.doctors.find_one({'_id': user_id})
            else:
                return jsonify({
                    'success': False,
                    'error': 'Invalid user type'
                }), 401
            
            if not current_user:
                return jsonify({
                    'success': False,
                    'error': 'User not found'
                }), 401
            
            # Add user info to current_user dict
            current_user['user_type'] = user_type
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'success': False,
                'error': 'Token has expired'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                'success': False,
                'error': 'Invalid token'
            }), 401
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Token validation failed: {str(e)}'
            }), 401
        
        # Pass current_user to the route
        return f(current_user, *args, **kwargs)
    
    return decorated

def doctor_required(f):
    """Decorator to ensure user is a doctor"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('user_type') != 'doctor':
            return jsonify({
                'success': False,
                'error': 'Access denied. Doctor privileges required.'
            }), 403
        return f(current_user, *args, **kwargs)
    return decorated

def patient_required(f):
    """Decorator to ensure user is a patient"""
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('user_type') != 'patient':
            return jsonify({
                'success': False,
                'error': 'Access denied. Patient privileges required.'
            }), 403
        return f(current_user, *args, **kwargs)
    return decorated