from flask import Blueprint, request
from datetime import datetime
from app.extensions import mongo
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from bson import ObjectId

connection_bp = Blueprint('connection', __name__)

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

@connection_bp.route('/request', methods=['POST'])
@token_required
def request_connection(current_user):
    """
    Patient requests connection with a doctor
    ---
    tags:
      - Patient-Doctor Connection
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - doctor_id
          properties:
            doctor_id:
              type: string
              example: "507f1f77bcf86cd799439011"
            connection_reason:
              type: string
              example: "Need consultation for diabetes management"
            conditions_being_treated:
              type: array
              items:
                type: string
              example: ["Diabetes", "Hypertension"]
            primary_doctor:
              type: boolean
              example: false
    responses:
      201:
        description: Connection request sent
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Only patients can request connections", 403)
        
        data = request.get_json()
        
        if not data or 'doctor_id' not in data:
            return error_response("doctor_id is required", 400)
        
        doctor_id = data['doctor_id']
        
        # Validate doctor exists
        doctor = mongo.db.users.find_one({
            "_id": ObjectId(doctor_id),
            "role": "doctor",
            "is_active": True
        })
        
        if not doctor:
            return error_response("Doctor not found", 404)
        
        if not doctor.get('is_verified', False):
            return error_response("Doctor is not verified yet", 403)
        
        if not doctor.get('is_accepting_patients', True):
            return error_response("Doctor is not accepting new patients", 403)
        
        # Check if connection already exists
        existing = mongo.db.connections.find_one({
            "patient_id": str(current_user['_id']),
            "doctor_id": doctor_id,
            "status": {"$in": ["pending", "active"]}
        })
        
        if existing:
            return error_response("Connection request already exists or active", 409)
        
        # Create connection
        connection = Connection(
            patient_id=str(current_user['_id']),
            doctor_id=doctor_id,
            request_initiated_by="patient"
        )
        
        if 'connection_reason' in data:
            connection.connection_reason = data['connection_reason']
        if 'conditions_being_treated' in data:
            connection.conditions_being_treated = data['conditions_being_treated']
        if 'primary_doctor' in data:
            connection.primary_doctor = data['primary_doctor']
        
        result = mongo.db.connections.insert_one(connection.to_dict())
        
        # Add to doctor's pending requests
        mongo.db.users.update_one(
            {"_id": ObjectId(doctor_id)},
            {"$addToSet": {"pending_connection_requests": str(result.inserted_id)}}
        )
        
        return success_response(
            "Connection request sent successfully",
            {
                "connection_id": str(result.inserted_id),
                "doctor_name": doctor['full_name'],
                "status": "pending"
            },
            201
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@connection_bp.route('/approve/<connection_id>', methods=['PUT'])
@token_required
def approve_connection(current_user, connection_id):
    """
    Doctor approves connection request
    ---
    tags:
      - Patient-Doctor Connection
    security:
      - Bearer: []
    parameters:
      - name: connection_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Connection approved
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can approve connections", 403)
        
        connection = mongo.db.connections.find_one({
            "_id": ObjectId(connection_id),
            "doctor_id": str(current_user['_id']),
            "status": "pending"
        })
        
        if not connection:
            return error_response("Connection request not found", 404)
        
        # Update connection status
        mongo.db.connections.update_one(
            {"_id": ObjectId(connection_id)},
            {"$set": {
                "status": "active",
                "approved_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }}
        )
        
        # Update doctor's lists
        mongo.db.users.update_one(
            {"_id": current_user['_id']},
            {
                "$pull": {"pending_connection_requests": connection_id},
                "$addToSet": {"connected_patients": connection['patient_id']}
            }
        )
        
        # Update patient's list
        mongo.db.users.update_one(
            {"_id": ObjectId(connection['patient_id'])},
            {"$addToSet": {"connected_doctors": str(current_user['_id'])}}
        )
        
        return success_response("Connection approved successfully")
        
    except Exception as e:
        return error_response(str(e), 500)


@connection_bp.route('/reject/<connection_id>', methods=['PUT'])
@token_required
def reject_connection(current_user, connection_id):
    """
    Doctor rejects connection request
    ---
    tags:
      - Patient-Doctor Connection
    security:
      - Bearer: []
    parameters:
      - name: connection_id
        in: path
        type: string
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            rejection_reason:
              type: string
    responses:
      200:
        description: Connection rejected
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can reject connections", 403)
        
        data = request.get_json() or {}
        
        connection = mongo.db.connections.find_one({
            "_id": ObjectId(connection_id),
            "doctor_id": str(current_user['_id']),
            "status": "pending"
        })
        
        if not connection:
            return error_response("Connection request not found", 404)
        
        # Update connection status
        mongo.db.connections.update_one(
            {"_id": ObjectId(connection_id)},
            {"$set": {
                "status": "rejected",
                "rejected_at": datetime.utcnow(),
                "rejection_reason": data.get('rejection_reason'),
                "updated_at": datetime.utcnow()
            }}
        )
        
        # Remove from doctor's pending requests
        mongo.db.users.update_one(
            {"_id": current_user['_id']},
            {"$pull": {"pending_connection_requests": connection_id}}
        )
        
        return success_response("Connection request rejected")
        
    except Exception as e:
        return error_response(str(e), 500)


@connection_bp.route('/my-connections', methods=['GET'])
@token_required
def get_my_connections(current_user):
    """
    Get user's connections (patients for doctors, doctors for patients)
    """
    try:
        user_id = str(current_user['_id'])
        role = current_user['role']
        
        if role == 'doctor':
            # Get connected patients
            user = mongo.db.users.find_one(
                {"_id": ObjectId(user_id)},
                {"connected_patients": 1}
            )
            
            if not user:
                return error_response("User not found", 404)
            
            connected_ids = user.get('connected_patients', [])
            
            # Fetch patient details
            connections = []
            if connected_ids:
                patients = list(mongo.db.users.find(
                    {"_id": {"$in": [ObjectId(pid) for pid in connected_ids]}, "role": "patient"},
                    {"password": 0}
                ))
                connections = convert_objectid(patients)
            
            return success_response(
                f"Found {len(connections)} connected patients",
                {"connections": connections, "count": len(connections), "type": "patients"}
            )
            
        elif role == 'patient':
            # Get connected doctors
            user = mongo.db.users.find_one(
                {"_id": ObjectId(user_id)},
                {"connected_doctors": 1}
            )
            
            if not user:
                return error_response("User not found", 404)
            
            connected_ids = user.get('connected_doctors', [])
            
            # Fetch doctor details
            connections = []
            if connected_ids:
                doctors = list(mongo.db.users.find(
                    {"_id": {"$in": [ObjectId(did) for did in connected_ids]}, "role": "doctor"},
                    {"password": 0}
                ))
                connections = convert_objectid(doctors)
            
            return success_response(
                f"Found {len(connections)} connected doctors",
                {"connections": connections, "count": len(connections), "type": "doctors"}
            )
        
        else:
            return error_response("Invalid user role", 400)
            
    except Exception as e:
        return error_response(str(e), 500)