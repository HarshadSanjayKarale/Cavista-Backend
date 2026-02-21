from flask import Blueprint, request
import bcrypt
import jwt
from datetime import datetime, timedelta
from app.extensions import mongo
from app.models.doctor.doctor_model import Doctor
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from app.config import Config

doctor_bp = Blueprint('doctor', __name__)

@doctor_bp.route('/register', methods=['POST'])
def register():
    """
    Register new doctor
    ---
    tags:
      - Doctor Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
            - full_name
            - specialization
            - license_number
          properties:
            email:
              type: string
              example: doctor@example.com
            password:
              type: string
              example: password123
            full_name:
              type: string
              example: Dr. Jane Smith
            phone:
              type: string
              example: "1234567890"
            specialization:
              type: string
              example: Cardiology
            license_number:
              type: string
              example: "LIC123456"
            qualification:
              type: string
              example: "MBBS, MD"
            experience_years:
              type: integer
              example: 10
            consultation_fee:
              type: number
              example: 500.00
            available_days:
              type: array
              items:
                type: string
              example: ["Monday", "Wednesday", "Friday"]
            available_hours:
              type: string
              example: "9:00 AM - 5:00 PM"
    responses:
      201:
        description: Doctor registered successfully
    """
    try:
        data = request.get_json()
        
        required_fields = ['email', 'password', 'full_name', 'specialization', 'license_number']
        if not all(field in data for field in required_fields):
            return error_response("Missing required fields", 400)
        
        email = data['email'].lower().strip()
        if '@' not in email:
            return error_response("Invalid email", 400)
        
        if mongo.db.users.find_one({"email": email}):
            return error_response("Email already exists", 409)
        
        if mongo.db.users.find_one({"license_number": data['license_number'], "role": "doctor"}):
            return error_response("License number already registered", 409)
        
        password = data['password']
        if len(password) < 6:
            return error_response("Password must be at least 6 characters", 400)
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        doctor = Doctor(
            email=email,
            password=hashed_password,
            full_name=data['full_name'].strip(),
            phone=data.get('phone'),
            specialization=data['specialization'],
            license_number=data['license_number'],
            qualification=data.get('qualification'),
            experience_years=data.get('experience_years'),
            consultation_fee=data.get('consultation_fee'),
            available_days=data.get('available_days', []),
            available_hours=data.get('available_hours')
        )
        
        result = mongo.db.users.insert_one(doctor.to_dict())
        
        return success_response(
            "Doctor registered successfully. Verification pending.",
            {
                "doctor_id": str(result.inserted_id),
                "email": email,
                "full_name": doctor.full_name,
                "is_verified": False
            },
            201
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/login', methods=['POST'])
def login():
    """
    Doctor login
    ---
    tags:
      - Doctor Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: doctor@example.com
            password:
              type: string
              example: password123
    responses:
      200:
        description: Login successful
    """
    try:
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return error_response("Missing email or password", 400)
        
        email = data['email'].lower().strip()
        user = mongo.db.users.find_one({"email": email, "role": "doctor"})
        
        if not user:
            return error_response("Invalid credentials", 401)
        
        if not user.get('is_active', True):
            return error_response("Account is deactivated", 403)
        
        if not bcrypt.checkpw(data['password'].encode('utf-8'), user['password']):
            return error_response("Invalid credentials", 401)
        
        token_payload = {
            'user_id': str(user['_id']),
            'email': user['email'],
            'role': user['role'],
            'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
        }
        
        token = jwt.encode(token_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
        
        mongo.db.users.update_one(
            {"_id": user['_id']},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return success_response(
            "Login successful",
            {
                "token": token,
                "doctor": {
                    "id": str(user['_id']),
                    "email": user['email'],
                    "full_name": user['full_name'],
                    "specialization": user.get('specialization'),
                    "is_verified": user.get('is_verified', False)
                }
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """
    Get doctor profile
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    responses:
      200:
        description: Profile retrieved successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Access denied. Doctor only.", 403)
        
        return success_response(
            "Profile retrieved",
            {
                "id": str(current_user['_id']),
                "email": current_user['email'],
                "full_name": current_user['full_name'],
                "phone": current_user.get('phone'),
                "specialization": current_user.get('specialization'),
                "license_number": current_user.get('license_number'),
                "qualification": current_user.get('qualification'),
                "experience_years": current_user.get('experience_years'),
                "consultation_fee": current_user.get('consultation_fee'),
                "available_days": current_user.get('available_days', []),
                "available_hours": current_user.get('available_hours'),
                "is_verified": current_user.get('is_verified', False),
                "patients": current_user.get('patients', []),
                "appointments": current_user.get('appointments', [])
            }
        )
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    """
    Update doctor profile
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            full_name:
              type: string
            phone:
              type: string
            qualification:
              type: string
            experience_years:
              type: integer
            consultation_fee:
              type: number
            available_days:
              type: array
              items:
                type: string
            available_hours:
              type: string
    responses:
      200:
        description: Profile updated successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Access denied. Doctor only.", 403)
        
        data = request.get_json()
        
        if not data:
            return error_response("No data provided", 400)
        
        allowed_fields = ['full_name', 'phone', 'qualification', 'experience_years',
                         'consultation_fee', 'available_days', 'available_hours']
        update_data = {k: v for k, v in data.items() if k in allowed_fields and v is not None}
        
        if not update_data:
            return error_response("No valid fields to update", 400)
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = mongo.db.users.update_one(
            {"_id": current_user['_id']},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            return success_response("Profile updated successfully")
        return error_response("No changes made", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/change-password', methods=['PUT'])
@token_required
def change_password(current_user):
    """
    Change doctor password
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - old_password
            - new_password
          properties:
            old_password:
              type: string
            new_password:
              type: string
    responses:
      200:
        description: Password changed successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Access denied. Doctor only.", 403)
        
        data = request.get_json()
        
        if not data or 'old_password' not in data or 'new_password' not in data:
            return error_response("Missing old_password or new_password", 400)
        
        if not bcrypt.checkpw(data['old_password'].encode('utf-8'), current_user['password']):
            return error_response("Invalid old password", 401)
        
        new_password = data['new_password']
        if len(new_password) < 6:
            return error_response("New password must be at least 6 characters", 400)
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        
        mongo.db.users.update_one(
            {"_id": current_user['_id']},
            {"$set": {
                "password": hashed_password,
                "updated_at": datetime.utcnow()
            }}
        )
        
        return success_response("Password changed successfully")
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    """
    Doctor logout
    ---
    tags:
      - Doctor Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: Logged out successfully
    """
    if current_user['role'] != 'doctor':
        return error_response("Access denied. Doctor only.", 403)
    return success_response("Logged out successfully")