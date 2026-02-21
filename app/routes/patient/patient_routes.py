from flask import Blueprint, request
import bcrypt
import jwt
from datetime import datetime, timedelta
from app.extensions import mongo
from app.models.patient.patient_model import Patient
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from app.config import Config

patient_bp = Blueprint('patient', __name__)

@patient_bp.route('/register', methods=['POST'])
def register():
    """
    Register new patient
    ---
    tags:
      - Patient Authentication
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
          properties:
            email:
              type: string
              example: patient@example.com
            password:
              type: string
              example: password123
            full_name:
              type: string
              example: John Doe
            phone:
              type: string
              example: "1234567890"
            date_of_birth:
              type: string
              example: "1990-01-01"
            gender:
              type: string
              example: Male
            blood_group:
              type: string
              example: "O+"
            address:
              type: string
              example: "123 Main St"
            emergency_contact:
              type: string
              example: "9876543210"
    responses:
      201:
        description: Patient registered successfully
    """
    try:
        data = request.get_json()
        
        required_fields = ['email', 'password', 'full_name']
        if not all(field in data for field in required_fields):
            return error_response("Missing required fields", 400)
        
        email = data['email'].lower().strip()
        if '@' not in email:
            return error_response("Invalid email", 400)
        
        if mongo.db.users.find_one({"email": email}):
            return error_response("Email already exists", 409)
        
        password = data['password']
        if len(password) < 6:
            return error_response("Password must be at least 6 characters", 400)
        
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        patient = Patient(
            email=email,
            password=hashed_password,
            full_name=data['full_name'].strip(),
            phone=data.get('phone'),
            date_of_birth=data.get('date_of_birth'),
            gender=data.get('gender'),
            blood_group=data.get('blood_group'),
            address=data.get('address'),
            emergency_contact=data.get('emergency_contact')
        )
        
        result = mongo.db.users.insert_one(patient.to_dict())
        
        return success_response(
            "Patient registered successfully",
            {
                "patient_id": str(result.inserted_id),
                "email": email,
                "full_name": patient.full_name
            },
            201
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/login', methods=['POST'])
def login():
    """
    Patient login
    ---
    tags:
      - Patient Authentication
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
              example: patient@example.com
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
        user = mongo.db.users.find_one({"email": email, "role": "patient"})
        
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
                "patient": {
                    "id": str(user['_id']),
                    "email": user['email'],
                    "full_name": user['full_name'],
                    "phone": user.get('phone'),
                    "blood_group": user.get('blood_group')
                }
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """
    Get patient profile
    ---
    tags:
      - Patient Profile
    security:
      - Bearer: []
    responses:
      200:
        description: Profile retrieved successfully
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        return success_response(
            "Profile retrieved",
            {
                "id": str(current_user['_id']),
                "email": current_user['email'],
                "full_name": current_user['full_name'],
                "phone": current_user.get('phone'),
                "date_of_birth": current_user.get('date_of_birth'),
                "gender": current_user.get('gender'),
                "blood_group": current_user.get('blood_group'),
                "address": current_user.get('address'),
                "emergency_contact": current_user.get('emergency_contact'),
                "medical_history": current_user.get('medical_history', []),
                "appointments": current_user.get('appointments', [])
            }
        )
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    """
    Update patient profile
    ---
    tags:
      - Patient Profile
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
            date_of_birth:
              type: string
            gender:
              type: string
            blood_group:
              type: string
            address:
              type: string
            emergency_contact:
              type: string
    responses:
      200:
        description: Profile updated successfully
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        data = request.get_json()
        
        if not data:
            return error_response("No data provided", 400)
        
        allowed_fields = ['full_name', 'phone', 'date_of_birth', 'gender', 
                         'blood_group', 'address', 'emergency_contact']
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


@patient_bp.route('/change-password', methods=['PUT'])
@token_required
def change_password(current_user):
    """
    Change patient password
    ---
    tags:
      - Patient Profile
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
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
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


@patient_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    """
    Patient logout
    ---
    tags:
      - Patient Authentication
    security:
      - Bearer: []
    responses:
      200:
        description: Logged out successfully
    """
    if current_user['role'] != 'patient':
        return error_response("Access denied. Patient only.", 403)
    return success_response("Logged out successfully")