from flask import Blueprint, request
import bcrypt
import jwt
from datetime import datetime, timedelta
from app.extensions import mongo
from app.models.doctor.doctor_model import Doctor
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from app.config import Config
from bson import ObjectId

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
        
        # Generate JWT token
        token_payload = {
            'user_id': str(result.inserted_id),
            'email': email,
            'role': 'doctor',
            'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRATION_HOURS)
        }
        
        token = jwt.encode(token_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
        
        return success_response(
            "Doctor registered successfully. Please complete your profile.",
            {
                "token": token,
                "doctor_id": str(result.inserted_id),
                "email": email,
                "full_name": doctor.full_name,
                "is_verified": False,
                "is_profile_complete": False,
                "message": "Please provide mobile number, degree, degree college, and clinic address to complete your profile"
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
                    "is_verified": user.get('is_verified', False),
                    "is_profile_complete": user.get('is_profile_complete', False)
                },
                "redirect_to_profile": not user.get('is_profile_complete', False)
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/complete-profile/<doctor_id>', methods=['POST'])
@token_required
def complete_profile(current_user, doctor_id):
    """
    Complete doctor profile (mandatory after signup)
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    parameters:
      - name: doctor_id
        in: path
        type: string
        required: true
        description: Doctor ID (returned from registration/login)
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - mobile_number
            - degree
            - degree_college
            - clinic_address
          properties:
            mobile_number:
              type: string
              example: "9876543210"
            degree:
              type: string
              example: "MBBS, MD"
            degree_college:
              type: string
              example: "Harvard Medical School"
            clinic_address:
              type: string
              example: "123 Medical Center, New York"
            clinic_name:
              type: string
              example: "Smith Heart Clinic"
            clinic_phone:
              type: string
              example: "1234567890"
            consultation_mode:
              type: array
              items:
                type: string
              example: ["in-person", "video"]
            languages_spoken:
              type: array
              items:
                type: string
              example: ["English", "Hindi"]
            registration_year:
              type: integer
              example: 2010
            medical_council:
              type: string
              example: "Medical Council of India"
    responses:
      200:
        description: Profile completed successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Access denied. Doctor only.", 403)
        
        # Verify doctor_id matches current user
        if str(current_user['_id']) != doctor_id:
            return error_response("You can only update your own profile", 403)
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['mobile_number', 'degree', 'degree_college', 'clinic_address']
        if not all(field in data for field in required_fields):
            return error_response("Missing required fields: mobile_number, degree, degree_college, clinic_address", 400)
        
        # Prepare update data
        update_data = {
            'mobile_number': data['mobile_number'],
            'degree': data['degree'],
            'degree_college': data['degree_college'],
            'clinic_address': data['clinic_address'],
            'is_profile_complete': True,
            'updated_at': datetime.utcnow()
        }
        
        # Optional fields
        if 'clinic_name' in data:
            update_data['clinic_name'] = data['clinic_name']
        if 'clinic_phone' in data:
            update_data['clinic_phone'] = data['clinic_phone']
        if 'consultation_mode' in data:
            update_data['consultation_mode'] = data['consultation_mode']
        if 'languages_spoken' in data:
            update_data['languages_spoken'] = data['languages_spoken']
        if 'registration_year' in data:
            update_data['registration_year'] = int(data['registration_year'])
        if 'medical_council' in data:
            update_data['medical_council'] = data['medical_council']
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(doctor_id)},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            return success_response(
                "Profile completed successfully. Awaiting verification.",
                {
                    "doctor_id": doctor_id,
                    "is_profile_complete": True,
                    "is_verified": False,
                    "message": "Your profile is under review by our team. You will be notified once verified."
                }
            )
        return error_response("No changes made", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/profile/<doctor_id>', methods=['GET'])
@token_required
def get_profile(current_user, doctor_id):
    """
    Get doctor profile
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    parameters:
      - name: doctor_id
        in: path
        type: string
        required: true
        description: Doctor ID
    responses:
      200:
        description: Profile retrieved successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Access denied. Doctor only.", 403)
        
        # Verify doctor_id matches current user
        if str(current_user['_id']) != doctor_id:
            return error_response("You can only view your own profile", 403)
        
        user = mongo.db.users.find_one({"_id": ObjectId(doctor_id), "role": "doctor"})
        
        if not user:
            return error_response("Doctor not found", 404)
        
        # Helper function to convert ObjectId to string recursively
        def convert_objectid(obj):
            if isinstance(obj, ObjectId):
                return str(obj)
            elif isinstance(obj, dict):
                return {key: convert_objectid(value) for key, value in obj.items()}
            elif isinstance(obj, list):
                return [convert_objectid(item) for item in obj]
            else:
                return obj
        
        # Convert all ObjectIds in user document
        user = convert_objectid(user)
        
        # Build response with explicit conversion
        appointments = user.get('appointments', [])
        connected_patients = user.get('connected_patients', [])
        pending_requests = user.get('pending_connection_requests', [])
        
        return success_response(
            "Profile retrieved",
            {
                "id": user['_id'],
                "email": user['email'],
                "full_name": user['full_name'],
                "phone": user.get('phone'),
                "specialization": user.get('specialization'),
                "license_number": user.get('license_number'),
                "qualification": user.get('qualification'),
                "experience_years": user.get('experience_years'),
                "consultation_fee": user.get('consultation_fee'),
                "available_days": user.get('available_days', []),
                "available_hours": user.get('available_hours'),
                
                # Required profile fields
                "mobile_number": user.get('mobile_number'),
                "degree": user.get('degree'),
                "degree_college": user.get('degree_college'),
                "clinic_address": user.get('clinic_address'),
                
                # Additional details
                "clinic_name": user.get('clinic_name'),
                "clinic_phone": user.get('clinic_phone'),
                "consultation_mode": user.get('consultation_mode', []),
                "languages_spoken": user.get('languages_spoken', []),
                "registration_year": user.get('registration_year'),
                "medical_council": user.get('medical_council'),
                "certifications": user.get('certifications', []),
                
                # Stats
                "rating": user.get('rating', 0.0),
                "total_reviews": user.get('total_reviews', 0),
                "total_consultations": user.get('total_consultations', 0),
                "connected_patients_count": len(connected_patients) if isinstance(connected_patients, list) else 0,
                "pending_requests_count": len(pending_requests) if isinstance(pending_requests, list) else 0,
                
                # Status
                "is_verified": user.get('is_verified', False),
                "is_profile_complete": user.get('is_profile_complete', False),
                "is_accepting_patients": user.get('is_accepting_patients', True),
                
                "appointments": appointments,
                "connected_patients": connected_patients,
                "pending_connection_requests": pending_requests
            }
        )
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/profile/<doctor_id>', methods=['PUT'])
@token_required
def update_profile(current_user, doctor_id):
    """
    Update doctor profile
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    parameters:
      - name: doctor_id
        in: path
        type: string
        required: true
        description: Doctor ID
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
            mobile_number:
              type: string
            clinic_address:
              type: string
            clinic_name:
              type: string
            clinic_phone:
              type: string
            consultation_mode:
              type: array
              items:
                type: string
            languages_spoken:
              type: array
              items:
                type: string
            is_accepting_patients:
              type: boolean
    responses:
      200:
        description: Profile updated successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Access denied. Doctor only.", 403)
        
        # Verify doctor_id matches current user
        if str(current_user['_id']) != doctor_id:
            return error_response("You can only update your own profile", 403)
        
        data = request.get_json()
        
        if not data:
            return error_response("No data provided", 400)
        
        allowed_fields = [
            'full_name', 'phone', 'qualification', 'experience_years',
            'consultation_fee', 'available_days', 'available_hours',
            'mobile_number', 'clinic_address', 'clinic_name', 'clinic_phone',
            'consultation_mode', 'languages_spoken', 'is_accepting_patients',
            'certifications', 'sub_specializations', 'conditions_treated'
        ]
        
        update_data = {k: v for k, v in data.items() if k in allowed_fields and v is not None}
        
        if not update_data:
            return error_response("No valid fields to update", 400)
        
        update_data['updated_at'] = datetime.utcnow()
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(doctor_id)},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            return success_response("Profile updated successfully", {"doctor_id": doctor_id})
        return error_response("No changes made", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@doctor_bp.route('/change-password/<doctor_id>', methods=['PUT'])
@token_required
def change_password(current_user, doctor_id):
    """
    Change doctor password
    ---
    tags:
      - Doctor Profile
    security:
      - Bearer: []
    parameters:
      - name: doctor_id
        in: path
        type: string
        required: true
        description: Doctor ID
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
        
        # Verify doctor_id matches current user
        if str(current_user['_id']) != doctor_id:
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
            {"_id": ObjectId(doctor_id)},
            {"$set": {
                "password": hashed_password,
                "updated_at": datetime.utcnow()
            }}
        )
        
        return success_response("Password changed successfully", {"doctor_id": doctor_id})
        
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


@doctor_bp.route('/search', methods=['GET'])
def search_doctors():
    """
    Search doctors by specialization, name, or location
    ---
    tags:
      - Doctor Search
    parameters:
      - name: specialization
        in: query
        type: string
        description: Filter by specialization
      - name: name
        in: query
        type: string
        description: Search by doctor name
      - name: location
        in: query
        type: string
        description: Search by location
      - name: min_rating
        in: query
        type: number
        description: Minimum rating
      - name: is_verified
        in: query
        type: boolean
        description: Only verified doctors
    responses:
      200:
        description: List of doctors
    """
    try:
        query = {"role": "doctor", "is_active": True, "is_profile_complete": True}
        
        # Filters
        if request.args.get('specialization'):
            query['specialization'] = {"$regex": request.args.get('specialization'), "$options": "i"}
        
        if request.args.get('name'):
            query['full_name'] = {"$regex": request.args.get('name'), "$options": "i"}
        
        if request.args.get('location'):
            query['clinic_address'] = {"$regex": request.args.get('location'), "$options": "i"}
        
        if request.args.get('min_rating'):
            query['rating'] = {"$gte": float(request.args.get('min_rating'))}
        
        if request.args.get('is_verified') == 'true':
            query['is_verified'] = True
        
        doctors = list(mongo.db.users.find(query, {
            'password': 0,
            'connected_patients': 0,
            'pending_connection_requests': 0
        }).limit(50))
        
        for doctor in doctors:
            doctor['_id'] = str(doctor['_id'])
        
        return success_response(
            f"Found {len(doctors)} doctors",
            {"doctors": doctors, "count": len(doctors)}
        )
        
    except Exception as e:
        return error_response(str(e), 500)