from flask import Blueprint, request
from datetime import datetime
from app.extensions import mongo
from app.models.medication.medication_model import MedicationPrescription, MedicationItem
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from bson import ObjectId

medication_bp = Blueprint('medication', __name__)


@medication_bp.route('/prescribe', methods=['POST'])
@token_required
def prescribe_medication(current_user):
    """
    Doctor prescribes medication for a patient
    ---
    tags:
      - Medication Management
    security:
      - Bearer: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
          properties:
            patient_id:
              type: string
              example: "507f1f77bcf86cd799439011"
              description: Patient ID to prescribe medication for
            diagnosis:
              type: string
              example: "Type 2 Diabetes"
            notes:
              type: string
              example: "Monitor blood sugar levels daily"
            prescription_duration_days:
              type: integer
              example: 30
            morning_medicines:
              type: array
              items:
                type: object
                properties:
                  name:
                    type: string
                    example: "Metformin"
                  dosage:
                    type: string
                    example: "500mg"
                  before_after_food:
                    type: string
                    enum: [before, after]
                    example: "after"
                  frequency:
                    type: string
                    example: "daily"
                  special_instructions:
                    type: string
                    example: "Take with plenty of water"
            afternoon_medicines:
              type: array
              items:
                type: object
                properties:
                  name:
                    type: string
                  dosage:
                    type: string
                  before_after_food:
                    type: string
                    enum: [before, after]
                  frequency:
                    type: string
                  special_instructions:
                    type: string
            evening_medicines:
              type: array
              items:
                type: object
                properties:
                  name:
                    type: string
                  dosage:
                    type: string
                  before_after_food:
                    type: string
                    enum: [before, after]
                  frequency:
                    type: string
                  special_instructions:
                    type: string
    responses:
      201:
        description: Prescription created successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can prescribe medication", 403)
        
        data = request.get_json()
        
        if not data or 'patient_id' not in data:
            return error_response("patient_id is required", 400)
        
        patient_id = data['patient_id']
        
        # Verify patient exists
        patient = mongo.db.users.find_one({
            "_id": ObjectId(patient_id),
            "role": "patient",
            "is_active": True
        })
        
        if not patient:
            return error_response("Patient not found", 404)
        
        # Verify active connection exists
        connection = mongo.db.connections.find_one({
            "patient_id": patient_id,
            "doctor_id": str(current_user['_id']),
            "status": "active"
        })
        
        if not connection:
            return error_response("No active connection with this patient. Connection required to prescribe.", 403)
        
        # Create prescription
        prescription = MedicationPrescription(
            doctor_id=str(current_user['_id']),
            patient_id=patient_id,
            prescribed_by_name=current_user['full_name']
        )
        
        # Add diagnosis and notes
        if 'diagnosis' in data:
            prescription.diagnosis = data['diagnosis']
        if 'notes' in data:
            prescription.notes = data['notes']
        if 'prescription_duration_days' in data:
            prescription.prescription_duration_days = int(data['prescription_duration_days'])
        
        # Process morning medicines
        if 'morning_medicines' in data and data['morning_medicines']:
            for med in data['morning_medicines']:
                if 'name' in med and 'dosage' in med and 'before_after_food' in med:
                    medicine = MedicationItem.create_medicine(
                        name=med['name'],
                        dosage=med['dosage'],
                        timing="morning",
                        before_after_food=med['before_after_food'],
                        frequency=med.get('frequency', 'daily'),
                        special_instructions=med.get('special_instructions')
                    )
                    prescription.morning_medicines.append(medicine)
        
        # Process afternoon medicines
        if 'afternoon_medicines' in data and data['afternoon_medicines']:
            for med in data['afternoon_medicines']:
                if 'name' in med and 'dosage' in med and 'before_after_food' in med:
                    medicine = MedicationItem.create_medicine(
                        name=med['name'],
                        dosage=med['dosage'],
                        timing="afternoon",
                        before_after_food=med['before_after_food'],
                        frequency=med.get('frequency', 'daily'),
                        special_instructions=med.get('special_instructions')
                    )
                    prescription.afternoon_medicines.append(medicine)
        
        # Process evening medicines
        if 'evening_medicines' in data and data['evening_medicines']:
            for med in data['evening_medicines']:
                if 'name' in med and 'dosage' in med and 'before_after_food' in med:
                    medicine = MedicationItem.create_medicine(
                        name=med['name'],
                        dosage=med['dosage'],
                        timing="evening",
                        before_after_food=med['before_after_food'],
                        frequency=med.get('frequency', 'daily'),
                        special_instructions=med.get('special_instructions')
                    )
                    prescription.evening_medicines.append(medicine)
        
        # Validate at least one medicine is prescribed
        total_medicines = (len(prescription.morning_medicines) + 
                          len(prescription.afternoon_medicines) + 
                          len(prescription.evening_medicines))
        
        if total_medicines == 0:
            return error_response("At least one medicine must be prescribed", 400)
        
        # Save prescription
        result = mongo.db.prescriptions.insert_one(prescription.to_dict())
        
        # Update patient's medication list
        mongo.db.users.update_one(
            {"_id": ObjectId(patient_id)},
            {
                "$push": {"prescriptions": str(result.inserted_id)},
                "$set": {"updated_at": datetime.utcnow()}
            }
        )
        
        return success_response(
            "Prescription created successfully",
            {
                "prescription_id": str(result.inserted_id),
                "patient_name": patient['full_name'],
                "doctor_name": current_user['full_name'],
                "total_medicines": total_medicines,
                "prescription_duration_days": prescription.prescription_duration_days,
                "summary": {
                    "morning": len(prescription.morning_medicines),
                    "afternoon": len(prescription.afternoon_medicines),
                    "evening": len(prescription.evening_medicines)
                }
            },
            201
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@medication_bp.route('/patient/<patient_id>', methods=['GET'])
@token_required
def get_patient_prescriptions(current_user, patient_id):
    """
    Get all prescriptions for a patient
    ---
    tags:
      - Medication Management
    security:
      - Bearer: []
    parameters:
      - name: patient_id
        in: path
        type: string
        required: true
        description: Patient ID
      - name: active_only
        in: query
        type: boolean
        description: Get only active prescriptions
      - name: doctor_id
        in: query
        type: string
        description: Filter by specific doctor
    responses:
      200:
        description: Patient prescriptions retrieved
    """
    try:
        # Verify patient exists
        patient = mongo.db.users.find_one({
            "_id": ObjectId(patient_id),
            "role": "patient"
        })
        
        if not patient:
            return error_response("Patient not found", 404)
        
        # Check authorization
        if current_user['role'] == 'patient':
            # Patient can only view their own prescriptions
            if str(current_user['_id']) != patient_id:
                return error_response("You can only view your own prescriptions", 403)
        elif current_user['role'] == 'doctor':
            # Doctor can only view prescriptions for connected patients
            connection = mongo.db.connections.find_one({
                "patient_id": patient_id,
                "doctor_id": str(current_user['_id']),
                "status": "active"
            })
            if not connection:
                return error_response("No active connection with this patient", 403)
        else:
            return error_response("Unauthorized access", 403)
        
        # Build query
        query = {"patient_id": patient_id}
        
        if request.args.get('active_only') == 'true':
            query['is_active'] = True
        
        if request.args.get('doctor_id'):
            query['doctor_id'] = request.args.get('doctor_id')
        
        # Get prescriptions
        prescriptions = list(mongo.db.prescriptions.find(query).sort("prescription_date", -1))
        
        # Format prescriptions
        formatted_prescriptions = []
        for prescription in prescriptions:
            prescription['_id'] = str(prescription['_id'])
            
            # Convert datetime to ISO format
            if 'prescription_date' in prescription:
                prescription['prescription_date'] = prescription['prescription_date'].isoformat()
            if 'created_at' in prescription:
                prescription['created_at'] = prescription['created_at'].isoformat()
            if 'updated_at' in prescription:
                prescription['updated_at'] = prescription['updated_at'].isoformat()
            
            # Convert datetime in medicine items
            for timing in ['morning_medicines', 'afternoon_medicines', 'evening_medicines']:
                if timing in prescription:
                    for med in prescription[timing]:
                        if 'added_at' in med and med['added_at']:
                            med['added_at'] = med['added_at'].isoformat()
            
            # Get doctor details
            doctor = mongo.db.users.find_one(
                {"_id": ObjectId(prescription['doctor_id'])},
                {"full_name": 1, "specialization": 1, "qualification": 1}
            )
            if doctor:
                prescription['doctor_info'] = {
                    "name": doctor.get('full_name'),
                    "specialization": doctor.get('specialization'),
                    "qualification": doctor.get('qualification')
                }
            
            formatted_prescriptions.append(prescription)
        
        return success_response(
            f"Found {len(prescriptions)} prescriptions",
            {
                "patient_name": patient['full_name'],
                "total_prescriptions": len(prescriptions),
                "prescriptions": formatted_prescriptions
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@medication_bp.route('/prescription/<prescription_id>', methods=['GET'])
@token_required
def get_prescription_details(current_user, prescription_id):
    """
    Get detailed prescription information
    ---
    tags:
      - Medication Management
    security:
      - Bearer: []
    parameters:
      - name: prescription_id
        in: path
        type: string
        required: true
        description: Prescription ID
    responses:
      200:
        description: Prescription details retrieved
    """
    try:
        prescription = mongo.db.prescriptions.find_one({"_id": ObjectId(prescription_id)})
        
        if not prescription:
            return error_response("Prescription not found", 404)
        
        # Check authorization
        if current_user['role'] == 'patient':
            if prescription['patient_id'] != str(current_user['_id']):
                return error_response("Unauthorized access", 403)
        elif current_user['role'] == 'doctor':
            if prescription['doctor_id'] != str(current_user['_id']):
                return error_response("Unauthorized access", 403)
        else:
            return error_response("Unauthorized access", 403)
        
        # Format prescription
        prescription['_id'] = str(prescription['_id'])
        
        if 'prescription_date' in prescription:
            prescription['prescription_date'] = prescription['prescription_date'].isoformat()
        if 'created_at' in prescription:
            prescription['created_at'] = prescription['created_at'].isoformat()
        if 'updated_at' in prescription:
            prescription['updated_at'] = prescription['updated_at'].isoformat()
        
        # Convert datetime in medicine items
        for timing in ['morning_medicines', 'afternoon_medicines', 'evening_medicines']:
            if timing in prescription:
                for med in prescription[timing]:
                    if 'added_at' in med and med['added_at']:
                        med['added_at'] = med['added_at'].isoformat()
        
        # Get patient and doctor details
        patient = mongo.db.users.find_one(
            {"_id": ObjectId(prescription['patient_id'])},
            {"full_name": 1, "age": 1, "gender": 1, "chronic_conditions": 1}
        )
        doctor = mongo.db.users.find_one(
            {"_id": ObjectId(prescription['doctor_id'])},
            {"full_name": 1, "specialization": 1, "qualification": 1, "license_number": 1}
        )
        
        prescription['patient_info'] = {
            "name": patient.get('full_name'),
            "age": patient.get('age'),
            "gender": patient.get('gender'),
            "chronic_conditions": patient.get('chronic_conditions', [])
        } if patient else None
        
        prescription['doctor_info'] = {
            "name": doctor.get('full_name'),
            "specialization": doctor.get('specialization'),
            "qualification": doctor.get('qualification'),
            "license_number": doctor.get('license_number')
        } if doctor else None
        
        return success_response("Prescription details retrieved", prescription)
        
    except Exception as e:
        return error_response(str(e), 500)


@medication_bp.route('/prescription/<prescription_id>/deactivate', methods=['PUT'])
@token_required
def deactivate_prescription(current_user, prescription_id):
    """
    Deactivate a prescription (Doctor only)
    ---
    tags:
      - Medication Management
    security:
      - Bearer: []
    parameters:
      - name: prescription_id
        in: path
        type: string
        required: true
        description: Prescription ID
      - in: body
        name: body
        schema:
          type: object
          properties:
            reason:
              type: string
              example: "Treatment completed"
    responses:
      200:
        description: Prescription deactivated
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can deactivate prescriptions", 403)
        
        data = request.get_json() or {}
        
        prescription = mongo.db.prescriptions.find_one({
            "_id": ObjectId(prescription_id),
            "doctor_id": str(current_user['_id'])
        })
        
        if not prescription:
            return error_response("Prescription not found or unauthorized", 404)
        
        mongo.db.prescriptions.update_one(
            {"_id": ObjectId(prescription_id)},
            {"$set": {
                "is_active": False,
                "deactivation_reason": data.get('reason'),
                "deactivated_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }}
        )
        
        return success_response("Prescription deactivated successfully")
        
    except Exception as e:
        return error_response(str(e), 500)


@medication_bp.route('/my-prescriptions', methods=['GET'])
@token_required
def get_my_prescriptions(current_user):
    """
    Get current user's prescriptions (Patient) or prescribed medications (Doctor)
    ---
    tags:
      - Medication Management
    security:
      - Bearer: []
    parameters:
      - name: active_only
        in: query
        type: boolean
        description: Get only active prescriptions
    responses:
      200:
        description: Prescriptions retrieved
    """
    try:
        if current_user['role'] == 'patient':
            return get_patient_prescriptions(current_user, str(current_user['_id']))
        elif current_user['role'] == 'doctor':
            # Get all prescriptions created by this doctor
            query = {"doctor_id": str(current_user['_id'])}
            
            if request.args.get('active_only') == 'true':
                query['is_active'] = True
            
            prescriptions = list(mongo.db.prescriptions.find(query).sort("prescription_date", -1))
            
            for prescription in prescriptions:
                prescription['_id'] = str(prescription['_id'])
                
                if 'prescription_date' in prescription:
                    prescription['prescription_date'] = prescription['prescription_date'].isoformat()
                
                # Get patient name
                patient = mongo.db.users.find_one(
                    {"_id": ObjectId(prescription['patient_id'])},
                    {"full_name": 1}
                )
                if patient:
                    prescription['patient_name'] = patient['full_name']
            
            return success_response(
                f"Found {len(prescriptions)} prescriptions",
                {
                    "total_prescriptions": len(prescriptions),
                    "prescriptions": prescriptions
                }
            )
        else:
            return error_response("Invalid role", 403)
        
    except Exception as e:
        return error_response(str(e), 500)