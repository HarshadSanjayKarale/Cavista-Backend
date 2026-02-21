from functools import wraps
from flask import request, jsonify
import jwt
from app.extensions import mongo
from app.config import Config
from bson import ObjectId

def token_required(f):
    """
    Decorator to protect routes that require authentication.
    Extracts JWT token from Authorization header and validates it.
    
    Usage:
        @auth_bp.route('/protected')
        @token_required
        def protected_route(current_user):
            return {"message": f"Hello {current_user['email']}"}
    
    Args:
        f: The function to be decorated
        
    Returns:
        Decorated function that requires valid JWT token
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Expected format: "Bearer <token>"
                parts = auth_header.split()
                if len(parts) == 2 and parts[0].lower() == 'bearer':
                    token = parts[1]
                else:
                    return jsonify({
                        "error": "Invalid token format. Use 'Bearer <token>'"
                    }), 401
            except IndexError:
                return jsonify({
                    "error": "Invalid Authorization header format"
                }), 401
        
        if not token:
            return jsonify({
                "error": "Authentication token is missing"
            }), 401
        
        try:
            # Decode token
            data = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
            
            # Get user from database
            current_user = mongo.db.users.find_one({"_id": ObjectId(data['user_id'])})
            
            if not current_user:
                return jsonify({
                    "error": "User not found"
                }), 401
            
            # Check if user is active
            if not current_user.get('is_active', True):
                return jsonify({
                    "error": "Account is deactivated. Please contact support."
                }), 403
                
        except jwt.ExpiredSignatureError:
            return jsonify({
                "error": "Token has expired. Please login again"
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "error": "Invalid token. Please login again"
            }), 401
        except Exception as e:
            return jsonify({
                "error": f"Authentication failed: {str(e)}"
            }), 401
        
        # Pass current_user to the decorated function
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    """
    Decorator to protect routes that require admin access.
    Must be used with @token_required decorator.
    
    Usage:
        @auth_bp.route('/admin-only')
        @token_required
        @admin_required
        def admin_route(current_user):
            return {"message": "Admin access granted"}
    
    Args:
        f: The function to be decorated
        
    Returns:
        Decorated function that requires admin role
    """
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get('role') != 'admin':
            return jsonify({
                "error": "Admin access required. You do not have permission to access this resource."
            }), 403
        return f(current_user, *args, **kwargs)
    
    return decorated

def role_required(*allowed_roles):
    """
    Decorator to protect routes based on specific roles.
    Must be used with @token_required decorator.
    
    Usage:
        @auth_bp.route('/moderator-or-admin')
        @token_required
        @role_required('admin', 'moderator')
        def restricted_route(current_user):
            return {"message": "Access granted"}
    
    Args:
        allowed_roles: Variable number of role strings that are allowed
        
    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):
            user_role = current_user.get('role', 'user')
            if user_role not in allowed_roles:
                return jsonify({
                    "error": f"Access denied. Required roles: {', '.join(allowed_roles)}"
                }), 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

def get_token_from_request():
    """
    Extract JWT token from request headers.
    
    Returns:
        str: JWT token if found, None otherwise
    """
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        try:
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                return parts[1]
        except:
            return None
    return None

def decode_token(token):
    """
    Decode JWT token and return payload.
    
    Args:
        token (str): JWT token
        
    Returns:
        dict: Token payload if valid, None otherwise
    """
    try:
        return jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
    except:
        return None