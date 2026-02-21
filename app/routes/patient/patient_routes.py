from flask import Blueprint, request
import bcrypt
import jwt
from datetime import datetime, timedelta
from app.extensions import mongo
from app.models.patient.patient_model import Patient
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from app.config import Config
from bson import ObjectId

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
        
        # Generate JWT token
        token_payload = {
            'user_id': str(result.inserted_id),
            'email': email,
            'role': 'patient',
            'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
        }
        
        token = jwt.encode(token_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
        
        return success_response(
            "Patient registered successfully. Please complete your profile.",
            {
                "token": token,
                "patient_id": str(result.inserted_id),
                "email": email,
                "full_name": patient.full_name,
                "is_profile_complete": False,
                "message": "Please provide age, weight, diet type, and workout level to complete your profile"
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
                    "blood_group": user.get('blood_group'),
                    "is_profile_complete": user.get('is_profile_complete', False)
                },
                "redirect_to_profile": not user.get('is_profile_complete', False)
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/complete-profile/<patient_id>', methods=['POST'])
@token_required
def complete_profile(current_user, patient_id):
    """
    Complete patient profile (mandatory after signup)
    ---
    tags:
      - Patient Profile
    security:
      - Bearer: []
    parameters:
      - name: patient_id
        in: path
        type: string
        required: true
        description: Patient ID (returned from registration/login)
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - age
            - weight
            - diet_type
            - workout_level
          properties:
            age:
              type: integer
              example: 30
              description: Age in years
            weight:
              type: number
              example: 70.5
              description: Weight in kg
            height:
              type: number
              example: 175
              description: Height in cm
            diet_type:
              type: string
              enum: [veg, nonveg, vegan]
              example: veg
            workout_level:
              type: string
              enum: [Beginner, Intermediate, Advanced]
              example: Intermediate
            chronic_conditions:
              type: array
              items:
                type: string
              example: ["Diabetes", "Hypertension"]
            allergies:
              type: array
              items:
                type: string
              example: ["Penicillin", "Peanuts"]
            current_medications:
              type: array
              items:
                type: string
              example: ["Metformin", "Lisinopril"]
            smoking_status:
              type: string
              enum: [never, former, current]
              example: never
            alcohol_consumption:
              type: string
              enum: [none, occasional, regular]
              example: occasional
    responses:
      200:
        description: Profile completed successfully
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        # Verify patient_id matches current user
        if str(current_user['_id']) != patient_id:
            return error_response("You can only update your own profile", 403)
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['age', 'weight', 'diet_type', 'workout_level']
        if not all(field in data for field in required_fields):
            return error_response("Missing required fields: age, weight, diet_type, workout_level", 400)
        
        # Validate enums
        valid_diet_types = ['veg', 'nonveg', 'vegan']
        valid_workout_levels = ['Beginner', 'Intermediate', 'Advanced']
        
        if data['diet_type'] not in valid_diet_types:
            return error_response(f"Invalid diet_type. Must be one of: {', '.join(valid_diet_types)}", 400)
        
        if data['workout_level'] not in valid_workout_levels:
            return error_response(f"Invalid workout_level. Must be one of: {', '.join(valid_workout_levels)}", 400)
        
        # Prepare update data
        update_data = {
            'age': int(data['age']),
            'weight': float(data['weight']),
            'height': float(data.get('height', 0)) if data.get('height') else None,
            'diet_type': data['diet_type'],
            'workout_level': data['workout_level'],
            'is_profile_complete': True,
            'updated_at': datetime.utcnow()
        }
        
        # Optional fields
        if 'chronic_conditions' in data:
            update_data['chronic_conditions'] = data['chronic_conditions']
        if 'allergies' in data:
            update_data['allergies'] = data['allergies']
        if 'current_medications' in data:
            update_data['current_medications'] = data['current_medications']
        if 'smoking_status' in data:
            update_data['smoking_status'] = data['smoking_status']
        if 'alcohol_consumption' in data:
            update_data['alcohol_consumption'] = data['alcohol_consumption']
        
        # Check if elderly (age > 60)
        if int(data['age']) > 60:
            update_data['is_elderly'] = True
            update_data['fall_detection_enabled'] = True
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(patient_id)},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            return success_response(
                "Profile completed successfully",
                {
                    "patient_id": patient_id,
                    "is_profile_complete": True,
                    "is_elderly": update_data.get('is_elderly', False),
                    "recommendations": "Based on your profile, we recommend connecting with doctors specializing in your health conditions."
                }
            )
        return error_response("No changes made", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/profile/<patient_id>', methods=['GET'])
@token_required
def get_profile(current_user, patient_id):
    """
    Get patient profile
    ---
    tags:
      - Patient Profile
    security:
      - Bearer: []
    parameters:
      - name: patient_id
        in: path
        type: string
        required: true
        description: Patient ID
    responses:
      200:
        description: Profile retrieved successfully
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        # Verify patient_id matches current user
        if str(current_user['_id']) != patient_id:
            return error_response("You can only view your own profile", 403)
        
        user = mongo.db.users.find_one({"_id": ObjectId(patient_id), "role": "patient"})
        
        if not user:
            return error_response("Patient not found", 404)
        
        # Calculate BMI if height and weight are available
        bmi = None
        if user.get('height') and user.get('weight'):
            height_m = user['height'] / 100
            bmi = round(user['weight'] / (height_m ** 2), 2)
        
        return success_response(
            "Profile retrieved",
            {
                "id": str(user['_id']),
                "email": user['email'],
                "full_name": user['full_name'],
                "phone": user.get('phone'),
                "date_of_birth": user.get('date_of_birth'),
                "gender": user.get('gender'),
                "blood_group": user.get('blood_group'),
                "address": user.get('address'),
                "emergency_contact": user.get('emergency_contact'),
                
                # Profile completion fields
                "age": user.get('age'),
                "weight": user.get('weight'),
                "height": user.get('height'),
                "bmi": bmi,
                "diet_type": user.get('diet_type'),
                "workout_level": user.get('workout_level'),
                
                # Health data
                "chronic_conditions": user.get('chronic_conditions', []),
                "allergies": user.get('allergies', []),
                "current_medications": user.get('current_medications', []),
                "family_medical_history": user.get('family_medical_history', []),
                
                # Lifestyle
                "stress_level": user.get('stress_level'),
                "sleep_hours_avg": user.get('sleep_hours_avg'),
                "smoking_status": user.get('smoking_status'),
                "alcohol_consumption": user.get('alcohol_consumption'),
                
                # Wearable
                "wearable_connected": user.get('wearable_connected', False),
                "last_vitals": user.get('last_vitals', {}),
                
                # Safety
                "is_elderly": user.get('is_elderly', False),
                "fall_detection_enabled": user.get('fall_detection_enabled', False),
                
                # System
                "medical_history": user.get('medical_history', []),
                "appointments": user.get('appointments', []),
                "connected_doctors_count": len(user.get('connected_doctors', [])),
                "is_profile_complete": user.get('is_profile_complete', False)
            }
        )
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/profile/<patient_id>', methods=['PUT'])
@token_required
def update_profile(current_user, patient_id):
    """
    Update patient profile
    ---
    tags:
      - Patient Profile
    security:
      - Bearer: []
    parameters:
      - name: patient_id
        in: path
        type: string
        required: true
        description: Patient ID
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
            age:
              type: integer
            weight:
              type: number
            height:
              type: number
            diet_type:
              type: string
            workout_level:
              type: string
            chronic_conditions:
              type: array
              items:
                type: string
            allergies:
              type: array
              items:
                type: string
            current_medications:
              type: array
              items:
                type: string
    responses:
      200:
        description: Profile updated successfully
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        # Verify patient_id matches current user
        if str(current_user['_id']) != patient_id:
            return error_response("You can only update your own profile", 403)
        
        data = request.get_json()
        
        if not data:
            return error_response("No data provided", 400)
        
        allowed_fields = [
            'full_name', 'phone', 'date_of_birth', 'gender', 'blood_group',
            'address', 'emergency_contact', 'age', 'weight', 'height',
            'diet_type', 'workout_level', 'chronic_conditions', 'allergies',
            'current_medications', 'stress_level', 'sleep_hours_avg',
            'smoking_status', 'alcohol_consumption'
        ]
        
        update_data = {k: v for k, v in data.items() if k in allowed_fields and v is not None}
        
        if not update_data:
            return error_response("No valid fields to update", 400)
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(patient_id)},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            return success_response("Profile updated successfully", {"patient_id": patient_id})
        return error_response("No changes made", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/change-password/<patient_id>', methods=['PUT'])
@token_required
def change_password(current_user, patient_id):
    """
    Change patient password
    ---
    tags:
      - Patient Profile
    security:
      - Bearer: []
    parameters:
      - name: patient_id
        in: path
        type: string
        required: true
        description: Patient ID
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
        
        # Verify patient_id matches current user
        if str(current_user['_id']) != patient_id:
            return error_response("You can only change your own password", 403)
        
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
            {"_id": ObjectId(patient_id)},
            {"$set": {
                "password": hashed_password,
                "updated_at": datetime.utcnow()
            }}
        )
        
        return success_response("Password changed successfully", {"patient_id": patient_id})
        
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