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


@patient_bp.route('/browse-doctors', methods=['GET'])
@token_required
def browse_doctors(current_user):
    """
    Browse available doctors with detailed information
    ---
    tags:
      - Patient Profile
    security:
      - Bearer: []
    parameters:
      - name: specialization
        in: query
        type: string
        description: Filter by specialization (e.g., Cardiology, Dermatology)
      - name: min_experience
        in: query
        type: integer
        description: Minimum years of experience
      - name: max_fee
        in: query
        type: number
        description: Maximum consultation fee
      - name: min_rating
        in: query
        type: number
        description: Minimum rating (0-5)
      - name: location
        in: query
        type: string
        description: Search by city or area
      - name: consultation_mode
        in: query
        type: string
        description: Filter by mode (in-person, video, phone)
      - name: language
        in: query
        type: string
        description: Filter by language spoken
      - name: is_accepting_patients
        in: query
        type: boolean
        description: Only show doctors accepting new patients
      - name: sort_by
        in: query
        type: string
        description: Sort by (rating, experience, fee_low, fee_high)
      - name: page
        in: query
        type: integer
        description: Page number (default 1)
      - name: limit
        in: query
        type: integer
        description: Results per page (default 20)
    responses:
      200:
        description: List of doctors with detailed information
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        # Build query - simplified to just show doctors with role="doctor"
        query = {
            "role": "doctor"
        }
        
        # Optional: only show active doctors if the field exists
        # Remove or comment these filters if you want to see all doctors
        # query["is_active"] = {"$ne": False}  # Show if is_active is True or doesn't exist
        
        # Apply filters
        if request.args.get('specialization'):
            query['specialization'] = {"$regex": request.args.get('specialization'), "$options": "i"}
        
        if request.args.get('min_experience'):
            query['experience_years'] = {"$gte": int(request.args.get('min_experience'))}
        
        if request.args.get('max_fee'):
            query['consultation_fee'] = {"$lte": float(request.args.get('max_fee'))}
        
        if request.args.get('min_rating'):
            query['rating'] = {"$gte": float(request.args.get('min_rating'))}
        
        if request.args.get('location'):
            query['clinic_address'] = {"$regex": request.args.get('location'), "$options": "i"}
        
        if request.args.get('consultation_mode'):
            query['consultation_mode'] = request.args.get('consultation_mode')
        
        if request.args.get('language'):
            query['languages_spoken'] = {"$in": [request.args.get('language')]}
        
        if request.args.get('is_accepting_patients') == 'true':
            query['is_accepting_patients'] = True
        
        # Pagination
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        skip = (page - 1) * limit
        
        # Sorting
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = -1  # Descending by default
        
        if sort_by == 'rating':
            sort_field = 'rating'
        elif sort_by == 'experience':
            sort_field = 'experience_years'
        elif sort_by == 'fee_low':
            sort_field = 'consultation_fee'
            sort_order = 1
        elif sort_by == 'fee_high':
            sort_field = 'consultation_fee'
        else:
            sort_field = 'created_at'
        
        # Get total count
        total_count = mongo.db.users.count_documents(query)
        
        # Fetch doctors with all relevant information
        doctors = list(mongo.db.users.find(
            query,
            {
                'password': 0  # Exclude password only
            }
        ).sort(sort_field, sort_order).skip(skip).limit(limit))
        
        # Convert ObjectIds to strings and enrich doctor data
        patient_id = str(current_user['_id'])
        formatted_doctors = []
        
        for doctor in doctors:
            # Convert all ObjectId fields to strings
            doctor['_id'] = str(doctor['_id'])
            
            # Convert datetime objects to ISO format strings
            if 'created_at' in doctor and doctor['created_at']:
                doctor['created_at'] = doctor['created_at'].isoformat()
            if 'updated_at' in doctor and doctor['updated_at']:
                doctor['updated_at'] = doctor['updated_at'].isoformat()
            if 'last_login' in doctor and doctor['last_login']:
                doctor['last_login'] = doctor['last_login'].isoformat()
            
            # Convert any ObjectIds in arrays (appointments, connected_patients, etc.)
            if 'appointments' in doctor and doctor['appointments']:
                doctor['appointments'] = [str(aid) if isinstance(aid, ObjectId) else aid for aid in doctor['appointments']]
            if 'connected_patients' in doctor and doctor['connected_patients']:
                doctor['connected_patients'] = [str(pid) if isinstance(pid, ObjectId) else pid for pid in doctor['connected_patients']]
            if 'pending_connection_requests' in doctor and doctor['pending_connection_requests']:
                doctor['pending_connection_requests'] = [str(rid) if isinstance(rid, ObjectId) else rid for rid in doctor['pending_connection_requests']]
            
            doctor_id = doctor['_id']
            
            # Check if already connected or pending
            existing_connection = mongo.db.connections.find_one({
                "patient_id": patient_id,
                "doctor_id": doctor_id,
                "status": {"$in": ["pending", "active"]}
            })
            
            if existing_connection:
                doctor['connection_status'] = existing_connection['status']
                doctor['can_send_request'] = False
            else:
                doctor['connection_status'] = 'none'
                doctor['can_send_request'] = doctor.get('is_accepting_patients', True)
            
            # Format doctor data for display
            doctor['display_info'] = {
                'basic': {
                    'name': doctor.get('full_name', 'N/A'),
                    'specialization': doctor.get('specialization', 'General'),
                    'qualification': doctor.get('qualification', 'N/A'),
                    'degree': doctor.get('degree', 'N/A')
                },
                'experience': {
                    'years': doctor.get('experience_years', 0),
                    'registration_year': doctor.get('registration_year', 'N/A'),
                    'medical_council': doctor.get('medical_council', 'N/A')
                },
                'practice': {
                    'clinic_name': doctor.get('clinic_name', 'N/A'),
                    'clinic_address': doctor.get('clinic_address', 'N/A'),
                    'clinic_phone': doctor.get('clinic_phone', doctor.get('mobile_number', 'N/A')),
                    'consultation_fee': doctor.get('consultation_fee', 0),
                    'consultation_mode': doctor.get('consultation_mode', []),
                    'available_days': doctor.get('available_days', []),
                    'available_hours': doctor.get('available_hours', 'N/A')
                },
                'ratings': {
                    'rating': round(doctor.get('rating', 0.0), 1),
                    'total_reviews': doctor.get('total_reviews', 0),
                    'total_consultations': doctor.get('total_consultations', 0)
                },
                'additional': {
                    'languages_spoken': doctor.get('languages_spoken', []),
                    'sub_specializations': doctor.get('sub_specializations', []),
                    'conditions_treated': doctor.get('conditions_treated', []),
                    'certifications': doctor.get('certifications', []),
                    'emergency_available': doctor.get('emergency_available', False)
                }
            }
            
            formatted_doctors.append(doctor)
        
        return success_response(
            f"Found {total_count} doctors",
            {
                "doctors": formatted_doctors,
                "pagination": {
                    "current_page": page,
                    "total_pages": (total_count + limit - 1) // limit if total_count > 0 else 0,
                    "total_count": total_count,
                    "per_page": limit,
                    "has_next": skip + limit < total_count,
                    "has_prev": page > 1
                },
                "filters_applied": {
                    "specialization": request.args.get('specialization'),
                    "min_experience": request.args.get('min_experience'),
                    "max_fee": request.args.get('max_fee'),
                    "min_rating": request.args.get('min_rating'),
                    "location": request.args.get('location'),
                    "consultation_mode": request.args.get('consultation_mode'),
                    "language": request.args.get('language'),
                    "sort_by": sort_by
                }
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@patient_bp.route('/doctor-details/<doctor_id>', methods=['GET'])
@token_required
def get_doctor_details(current_user, doctor_id):
    """
    Get detailed information about a specific doctor
    ---
    tags:
      - Patient Profile
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
        description: Detailed doctor information
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Access denied. Patient only.", 403)
        
        doctor = mongo.db.users.find_one(
            {
                "_id": ObjectId(doctor_id),
                "role": "doctor",
                "is_active": True,
                "is_verified": True
            },
            {
                'password': 0,
                'connected_patients': 0,
                'pending_connection_requests': 0
            }
        )
        
        if not doctor:
            return error_response("Doctor not found or not available", 404)
        
        # Convert ObjectId to string
        doctor['_id'] = str(doctor['_id'])
        
        # Convert datetime objects to ISO format strings
        if 'created_at' in doctor and doctor['created_at']:
            doctor['created_at'] = doctor['created_at'].isoformat()
        if 'updated_at' in doctor and doctor['updated_at']:
            doctor['updated_at'] = doctor['updated_at'].isoformat()
        if 'last_login' in doctor and doctor['last_login']:
            doctor['last_login'] = doctor['last_login'].isoformat()
        
        # Check connection status
        patient_id = str(current_user['_id'])
        existing_connection = mongo.db.connections.find_one({
            "patient_id": patient_id,
            "doctor_id": doctor_id,
            "status": {"$in": ["pending", "active"]}
        })
        
        if existing_connection:
            doctor['connection_status'] = existing_connection['status']
            doctor['connection_id'] = str(existing_connection['_id'])
            doctor['can_send_request'] = False
        else:
            doctor['connection_status'] = 'none'
            doctor['can_send_request'] = doctor.get('is_accepting_patients', True)
        
        # Calculate availability percentage
        available_days = doctor.get('available_days', [])
        availability_percentage = (len(available_days) / 7) * 100 if available_days else 0
        
        return success_response(
            "Doctor details retrieved",
            {
                "doctor": doctor,
                "availability_percentage": round(availability_percentage, 1),
                "recommendation": _get_match_recommendation(current_user, doctor)
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


def _get_match_recommendation(patient, doctor):
    """Helper function to provide match recommendation"""
    match_score = 0
    reasons = []
    
    # Check if doctor treats patient's chronic conditions
    patient_conditions = patient.get('chronic_conditions', [])
    doctor_conditions = doctor.get('conditions_treated', [])
    
    if patient_conditions and doctor_conditions:
        matching_conditions = set(patient_conditions) & set(doctor_conditions)
        if matching_conditions:
            match_score += 30
            reasons.append(f"Specializes in treating: {', '.join(matching_conditions)}")
    
    # Check rating
    rating = doctor.get('rating', 0)
    if rating >= 4.5:
        match_score += 25
        reasons.append(f"Highly rated ({rating}/5)")
    elif rating >= 4.0:
        match_score += 15
        reasons.append(f"Well rated ({rating}/5)")
    
    # Check experience
    experience = doctor.get('experience_years', 0)
    if experience >= 10:
        match_score += 20
        reasons.append(f"{experience} years of experience")
    elif experience >= 5:
        match_score += 10
        reasons.append(f"{experience} years of experience")
    
    # Check consultation modes
    consultation_modes = doctor.get('consultation_mode', [])
    if 'video' in consultation_modes:
        match_score += 10
        reasons.append("Offers video consultations")
    
    # Check if elderly patient and doctor has relevant experience
    if patient.get('is_elderly') and 'Geriatrics' in doctor.get('sub_specializations', []):
        match_score += 15
        reasons.append("Experienced with elderly care")
    
    return {
        "match_score": min(match_score, 100),
        "reasons": reasons,
        "recommendation_level": "Highly Recommended" if match_score >= 70 else "Recommended" if match_score >= 50 else "Available"
    }