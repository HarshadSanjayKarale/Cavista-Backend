from flask import Blueprint, request
from datetime import datetime, timedelta
from app.extensions import mongo
from app.models.appointment.appointment_model import Appointment
from app.utils.auth_utils import token_required
from app.utils.response_utils import success_response, error_response
from bson import ObjectId

appointment_bp = Blueprint('appointment', __name__)


@appointment_bp.route('/request', methods=['POST'])
@token_required
def request_appointment(current_user):
    """
    Patient requests appointment with doctor
    ---
    tags:
      - Appointments
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
            - patient_id
            - appointment_type
            - reason
          properties:
            doctor_id:
              type: string
              example: "699955bb562fe7307f7c1022"
            patient_id:
              type: string
              example: "69995140635e07c46278e903"
            appointment_type:
              type: string
              enum: [consultation, follow-up, emergency, checkup]
              example: "consultation"
            reason:
              type: string
              example: "Regular checkup for hypertension"
            symptoms:
              type: array
              items:
                type: string
              example: ["High BP", "Headache"]
            preferred_date:
              type: string
              format: date
              example: "2026-02-25"
            preferred_time_slot:
              type: string
              example: "10:00 AM - 11:00 AM"
            notes:
              type: string
              example: "I've been feeling dizzy lately"
            is_urgent:
              type: boolean
              example: false
    responses:
      201:
        description: Appointment request sent successfully
      403:
        description: Invalid request
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['doctor_id', 'patient_id', 'appointment_type', 'reason']
        if not all(field in data for field in required_fields):
            return error_response("Missing required fields: doctor_id, patient_id, appointment_type, reason", 400)
        
        doctor_id = data['doctor_id']
        patient_id = data['patient_id']
        
        # Verify the logged-in user matches the patient_id (security check)
        if current_user['role'] == 'patient' and str(current_user['_id']) != patient_id:
            return error_response("You can only create appointments for yourself", 403)
        
        # Check if patient exists
        patient = mongo.db.users.find_one({
            "_id": ObjectId(patient_id),
            "role": "patient"
        })
        
        if not patient:
            return error_response("Patient not found", 404)
        
        # Check if doctor exists and is active
        doctor = mongo.db.users.find_one({
            "_id": ObjectId(doctor_id),
            "role": "doctor",
            "is_active": True
        })
        
        if not doctor:
            return error_response("Doctor not found or inactive", 404)
        
        if not doctor.get('is_accepting_patients', True):
            return error_response("Doctor is not accepting appointments currently", 400)
        
        # Validate appointment type
        valid_types = ['consultation', 'follow-up', 'emergency', 'checkup']
        if data['appointment_type'] not in valid_types:
            return error_response(f"Invalid appointment_type. Must be one of: {', '.join(valid_types)}", 400)
        
        # Check if connection exists, if not create one automatically
        connection = mongo.db.connections.find_one({
            "patient_id": ObjectId(patient_id),
            "doctor_id": ObjectId(doctor_id)
        })
        
        if not connection:
            # Auto-create connection
            connection_data = {
                "patient_id": ObjectId(patient_id),
                "doctor_id": ObjectId(doctor_id),
                "status": "active",
                "connected_at": datetime.utcnow(),
                "connection_type": "appointment_based"
            }
            connection_result = mongo.db.connections.insert_one(connection_data)
            connection_id = connection_result.inserted_id
        else:
            connection_id = connection['_id']
            # Update connection status to active if it was inactive
            if connection.get('status') != 'active':
                mongo.db.connections.update_one(
                    {"_id": connection_id},
                    {"$set": {"status": "active"}}
                )
        
        # Create appointment
        appointment = Appointment(
            patient_id=ObjectId(patient_id),
            doctor_id=ObjectId(doctor_id),
            connection_id=connection_id,
            appointment_type=data['appointment_type'],
            reason=data['reason'],
            symptoms=data.get('symptoms', []),
            preferred_date=data.get('preferred_date'),
            preferred_time_slot=data.get('preferred_time_slot'),
            notes=data.get('notes'),
            is_urgent=data.get('is_urgent', False)
        )
        
        # Set consultation fee from doctor profile
        if doctor.get('consultation_fee'):
            appointment.consultation_fee = doctor['consultation_fee']
        
        result = mongo.db.appointments.insert_one(appointment.to_dict())
        
        # Add appointment reference to both patient and doctor
        mongo.db.users.update_one(
            {"_id": ObjectId(patient_id)},
            {"$addToSet": {"appointments": result.inserted_id}}
        )
        
        mongo.db.users.update_one(
            {"_id": ObjectId(doctor_id)},
            {"$addToSet": {"appointments": result.inserted_id}}
        )
        
        return success_response(
            "Appointment request sent successfully",
            {
                "appointment_id": str(result.inserted_id),
                "patient": {
                    "id": str(patient['_id']),
                    "name": patient['full_name'],
                    "email": patient['email']
                },
                "doctor": {
                    "id": str(doctor['_id']),
                    "name": doctor['full_name'],
                    "specialization": doctor.get('specialization')
                },
                "appointment_type": data['appointment_type'],
                "status": "pending",
                "preferred_date": data.get('preferred_date'),
                "preferred_time_slot": data.get('preferred_time_slot'),
                "is_urgent": data.get('is_urgent', False),
                "requested_at": appointment.requested_at.isoformat(),
                "message": f"Your appointment request has been sent to {doctor['full_name']}. You will be notified once confirmed."
            },
            201
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/my-appointments', methods=['GET'])
@token_required
def get_my_appointments(current_user):
    """
    Get all appointments for current user (patient or doctor)
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: status
        in: query
        type: string
        description: Filter by status (pending, confirmed, completed, cancelled)
      - name: doctor_id
        in: query
        type: string
        description: Filter by doctor (patient only)
      - name: patient_id
        in: query
        type: string
        description: Filter by patient (doctor only)
      - name: from_date
        in: query
        type: string
        format: date
        description: Filter appointments from this date
      - name: to_date
        in: query
        type: string
        format: date
        description: Filter appointments until this date
    responses:
      200:
        description: List of appointments
    """
    try:
        query = {}
        
        # Filter based on user role
        if current_user['role'] == 'patient':
            query['patient_id'] = ObjectId(current_user['_id'])
            
            # Patient can filter by doctor
            if request.args.get('doctor_id'):
                query['doctor_id'] = ObjectId(request.args.get('doctor_id'))
                
        elif current_user['role'] == 'doctor':
            query['doctor_id'] = ObjectId(current_user['_id'])
            
            # Doctor can filter by patient
            if request.args.get('patient_id'):
                query['patient_id'] = ObjectId(request.args.get('patient_id'))
        
        # Filter by status
        if request.args.get('status'):
            query['status'] = request.args.get('status')
        
        # Filter by date range
        if request.args.get('from_date') or request.args.get('to_date'):
            date_query = {}
            if request.args.get('from_date'):
                date_query['$gte'] = request.args.get('from_date')
            if request.args.get('to_date'):
                date_query['$lte'] = request.args.get('to_date')
            query['confirmed_date'] = date_query
        
        # Get appointments
        appointments = list(mongo.db.appointments.find(query).sort('requested_at', -1))
        
        # Enrich with patient and doctor details
        for appointment in appointments:
            # Get patient details
            patient = mongo.db.users.find_one(
                {"_id": appointment['patient_id']},
                {"password": 0}
            )
            appointment['patient'] = {
                "id": str(patient['_id']),
                "name": patient['full_name'],
                "email": patient['email'],
                "age": patient.get('age'),
                "blood_group": patient.get('blood_group'),
                "phone": patient.get('phone')
            } if patient else None
            
            # Get doctor details
            doctor = mongo.db.users.find_one(
                {"_id": appointment['doctor_id']},
                {"password": 0}
            )
            appointment['doctor'] = {
                "id": str(doctor['_id']),
                "name": doctor['full_name'],
                "email": doctor['email'],
                "specialization": doctor.get('specialization'),
                "clinic_address": doctor.get('clinic_address'),
                "mobile_number": doctor.get('mobile_number')
            } if doctor else None
            
            # Convert ObjectIds to strings
            appointment['_id'] = str(appointment['_id'])
            appointment['patient_id'] = str(appointment['patient_id'])
            appointment['doctor_id'] = str(appointment['doctor_id'])
            appointment['connection_id'] = str(appointment['connection_id'])
        
        # Count by status
        status_breakdown = {
            "pending": len([a for a in appointments if a['status'] == 'pending']),
            "confirmed": len([a for a in appointments if a['status'] == 'confirmed']),
            "completed": len([a for a in appointments if a['status'] == 'completed']),
            "cancelled": len([a for a in appointments if a['status'] == 'cancelled'])
        }
        
        return success_response(
            "Appointments retrieved successfully",
            {
                "appointments": appointments,
                "count": len(appointments),
                "status_breakdown": status_breakdown
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/connected-doctors', methods=['GET'])
@token_required
def get_connected_doctors(current_user):
    """
    Get list of doctors patient is connected with (for appointment booking)
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    responses:
      200:
        description: List of connected doctors
    """
    try:
        if current_user['role'] != 'patient':
            return error_response("Only patients can access this endpoint", 403)
        
        # Get active connections
        connections = list(mongo.db.connections.find({
            "patient_id": ObjectId(current_user['_id']),
            "status": "active"
        }))
        
        if not connections:
            return success_response(
                "No connected doctors found",
                {"doctors": [], "count": 0}
            )
        
        # Get doctor details
        doctor_ids = [conn['doctor_id'] for conn in connections]
        doctors = list(mongo.db.users.find(
            {
                "_id": {"$in": doctor_ids},
                "role": "doctor",
                "is_active": True
            },
            {"password": 0}
        ))
        
        # Format doctor data
        connected_doctors = []
        for doctor in doctors:
            connected_doctors.append({
                "id": str(doctor['_id']),
                "name": doctor['full_name'],
                "email": doctor['email'],
                "specialization": doctor.get('specialization'),
                "qualification": doctor.get('qualification'),
                "degree": doctor.get('degree'),
                "experience_years": doctor.get('experience_years'),
                "consultation_fee": doctor.get('consultation_fee'),
                "clinic_name": doctor.get('clinic_name'),
                "clinic_address": doctor.get('clinic_address'),
                "mobile_number": doctor.get('mobile_number'),
                "available_days": doctor.get('available_days', []),
                "available_hours": doctor.get('available_hours'),
                "consultation_mode": doctor.get('consultation_mode', []),
                "is_accepting_patients": doctor.get('is_accepting_patients', True),
                "rating": doctor.get('rating', 0)
            })
        
        return success_response(
            f"Found {len(connected_doctors)} connected doctors",
            {
                "doctors": connected_doctors,
                "count": len(connected_doctors)
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/confirm/<appointment_id>', methods=['PUT'])
@token_required
def confirm_appointment(current_user, appointment_id):
    """
    Doctor confirms appointment with date and time
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: appointment_id
        in: path
        type: string
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - confirmed_date
            - confirmed_time
          properties:
            confirmed_date:
              type: string
              format: date
              example: "2026-02-25"
            confirmed_time:
              type: string
              example: "10:00 AM"
            duration_minutes:
              type: integer
              example: 30
            consultation_mode:
              type: string
              enum: [in-person, video-call, phone-call]
              example: "in-person"
            doctor_notes:
              type: string
              example: "Please bring previous reports"
    responses:
      200:
        description: Appointment confirmed successfully
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can confirm appointments", 403)
        
        data = request.get_json()
        
        # Validate required fields
        if not data or 'confirmed_date' not in data or 'confirmed_time' not in data:
            return error_response("confirmed_date and confirmed_time are required", 400)
        
        # Get appointment
        appointment = mongo.db.appointments.find_one({
            "_id": ObjectId(appointment_id),
            "doctor_id": ObjectId(current_user['_id'])
        })
        
        if not appointment:
            return error_response("Appointment not found or you don't have access", 404)
        
        if appointment['status'] != 'pending':
            return error_response(f"Appointment is already {appointment['status']}", 400)
        
        # Validate consultation mode
        if 'consultation_mode' in data:
            valid_modes = ['in-person', 'video-call', 'phone-call']
            if data['consultation_mode'] not in valid_modes:
                return error_response(f"Invalid consultation_mode. Must be one of: {', '.join(valid_modes)}", 400)
        
        # Check for scheduling conflicts
        conflict = mongo.db.appointments.find_one({
            "doctor_id": ObjectId(current_user['_id']),
            "status": "confirmed",
            "confirmed_date": data['confirmed_date'],
            "confirmed_time": data['confirmed_time']
        })
        
        if conflict:
            return error_response("You already have an appointment scheduled at this time. Please choose a different time.", 409)
        
        # Update appointment
        update_data = {
            "status": "confirmed",
            "confirmed_date": data['confirmed_date'],
            "confirmed_time": data['confirmed_time'],
            "duration_minutes": data.get('duration_minutes', 30),
            "consultation_mode": data.get('consultation_mode', 'in-person'),
            "doctor_notes": data.get('doctor_notes'),
            "confirmed_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }
        
        result = mongo.db.appointments.update_one(
            {"_id": ObjectId(appointment_id)},
            {"$set": update_data}
        )
        
        if result.modified_count > 0:
            # Get patient details for response
            patient = mongo.db.users.find_one(
                {"_id": appointment['patient_id']},
                {"full_name": 1, "email": 1}
            )
            
            return success_response(
                "Appointment confirmed successfully",
                {
                    "appointment_id": appointment_id,
                    "patient": {
                        "id": str(patient['_id']),
                        "name": patient['full_name'],
                        "email": patient['email']
                    },
                    "confirmed_date": data['confirmed_date'],
                    "confirmed_time": data['confirmed_time'],
                    "duration_minutes": update_data['duration_minutes'],
                    "consultation_mode": update_data['consultation_mode'],
                    "status": "confirmed",
                    "message": f"Appointment confirmed for {data['confirmed_date']} at {data['confirmed_time']}"
                }
            )
        
        return error_response("Failed to confirm appointment", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/calendar', methods=['GET'])
@token_required
def get_calendar(current_user):
    """
    Get doctor's appointment calendar
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: month
        in: query
        type: string
        description: Month in YYYY-MM format
        example: "2026-02"
      - name: date
        in: query
        type: string
        format: date
        description: Specific date in YYYY-MM-DD format
        example: "2026-02-25"
    responses:
      200:
        description: Calendar with confirmed appointments
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can access calendar", 403)
        
        query = {
            "doctor_id": ObjectId(current_user['_id']),
            "status": "confirmed"
        }
        
        # Filter by specific date or month
        if request.args.get('date'):
            query['confirmed_date'] = request.args.get('date')
        elif request.args.get('month'):
            # Get all dates in the month
            month = request.args.get('month')
            query['confirmed_date'] = {
                "$regex": f"^{month}"
            }
        
        # Get confirmed appointments
        appointments = list(mongo.db.appointments.find(query).sort([
            ('confirmed_date', 1),
            ('confirmed_time', 1)
        ]))
        
        # Enrich with patient details
        calendar_appointments = []
        for appointment in appointments:
            patient = mongo.db.users.find_one(
                {"_id": appointment['patient_id']},
                {"full_name": 1, "email": 1, "phone": 1, "age": 1}
            )
            
            calendar_appointments.append({
                "appointment_id": str(appointment['_id']),
                "patient": {
                    "id": str(patient['_id']),
                    "name": patient['full_name'],
                    "email": patient['email'],
                    "phone": patient.get('phone'),
                    "age": patient.get('age')
                },
                "appointment_type": appointment['appointment_type'],
                "reason": appointment['reason'],
                "date": appointment['confirmed_date'],
                "time": appointment['confirmed_time'],
                "duration_minutes": appointment.get('duration_minutes', 30),
                "consultation_mode": appointment.get('consultation_mode'),
                "is_urgent": appointment.get('is_urgent', False),
                "notes": appointment.get('notes'),
                "doctor_notes": appointment.get('doctor_notes')
            })
        
        return success_response(
            f"Found {len(calendar_appointments)} appointments",
            {
                "appointments": calendar_appointments,
                "count": len(calendar_appointments)
            }
        )
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/reject/<appointment_id>', methods=['PUT'])
@token_required
def reject_appointment(current_user, appointment_id):
    """
    Doctor rejects appointment request
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: appointment_id
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
              example: "Not available on requested date"
    responses:
      200:
        description: Appointment rejected
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can reject appointments", 403)
        
        data = request.get_json() or {}
        
        # Get appointment
        appointment = mongo.db.appointments.find_one({
            "_id": ObjectId(appointment_id),
            "doctor_id": ObjectId(current_user['_id'])
        })
        
        if not appointment:
            return error_response("Appointment not found", 404)
        
        if appointment['status'] != 'pending':
            return error_response(f"Cannot reject appointment with status: {appointment['status']}", 400)
        
        # Update appointment
        result = mongo.db.appointments.update_one(
            {"_id": ObjectId(appointment_id)},
            {
                "$set": {
                    "status": "cancelled",
                    "rejection_reason": data.get('rejection_reason'),
                    "cancelled_at": datetime.utcnow(),
                    "cancelled_by": "doctor",
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            return success_response(
                "Appointment request rejected",
                {
                    "appointment_id": appointment_id,
                    "status": "cancelled",
                    "rejection_reason": data.get('rejection_reason')
                }
            )
        
        return error_response("Failed to reject appointment", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/cancel/<appointment_id>', methods=['PUT'])
@token_required
def cancel_appointment(current_user, appointment_id):
    """
    Cancel appointment (Patient or Doctor)
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: appointment_id
        in: path
        type: string
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            cancellation_reason:
              type: string
              example: "Unable to attend due to emergency"
    responses:
      200:
        description: Appointment cancelled
    """
    try:
        data = request.get_json() or {}
        
        # Get appointment
        query = {"_id": ObjectId(appointment_id)}
        if current_user['role'] == 'patient':
            query['patient_id'] = ObjectId(current_user['_id'])
        elif current_user['role'] == 'doctor':
            query['doctor_id'] = ObjectId(current_user['_id'])
        
        appointment = mongo.db.appointments.find_one(query)
        
        if not appointment:
            return error_response("Appointment not found", 404)
        
        if appointment['status'] in ['cancelled', 'completed']:
            return error_response(f"Cannot cancel appointment with status: {appointment['status']}", 400)
        
        # Update appointment
        result = mongo.db.appointments.update_one(
            {"_id": ObjectId(appointment_id)},
            {
                "$set": {
                    "status": "cancelled",
                    "rejection_reason": data.get('cancellation_reason'),
                    "cancelled_at": datetime.utcnow(),
                    "cancelled_by": current_user['role'],
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        if result.modified_count > 0:
            return success_response(
                "Appointment cancelled successfully",
                {
                    "appointment_id": appointment_id,
                    "status": "cancelled",
                    "cancelled_by": current_user['role']
                }
            )
        
        return error_response("Failed to cancel appointment", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/complete/<appointment_id>', methods=['PUT'])
@token_required
def complete_appointment(current_user, appointment_id):
    """
    Mark appointment as completed (Doctor only)
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: appointment_id
        in: path
        type: string
        required: true
      - in: body
        name: body
        schema:
          type: object
          properties:
            diagnosis:
              type: string
              example: "Hypertension Stage 1"
            prescription:
              type: string
              example: "Lisinopril 10mg once daily"
            doctor_notes:
              type: string
              example: "Patient responding well to medication"
    responses:
      200:
        description: Appointment completed
    """
    try:
        if current_user['role'] != 'doctor':
            return error_response("Only doctors can complete appointments", 403)
        
        data = request.get_json() or {}
        
        appointment = mongo.db.appointments.find_one({
            "_id": ObjectId(appointment_id),
            "doctor_id": ObjectId(current_user['_id'])
        })
        
        if not appointment:
            return error_response("Appointment not found", 404)
        
        if appointment['status'] != 'confirmed':
            return error_response(f"Cannot complete appointment with status: {appointment['status']}", 400)
        
        # Update appointment
        result = mongo.db.appointments.update_one(
            {"_id": ObjectId(appointment_id)},
            {
                "$set": {
                    "status": "completed",
                    "diagnosis": data.get('diagnosis'),
                    "prescription": data.get('prescription'),
                    "doctor_notes": data.get('doctor_notes'),
                    "completed_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            }
        )
        
        # Update doctor's total consultations
        mongo.db.users.update_one(
            {"_id": ObjectId(current_user['_id'])},
            {"$inc": {"total_consultations": 1}}
        )
        
        if result.modified_count > 0:
            return success_response(
                "Appointment marked as completed",
                {
                    "appointment_id": appointment_id,
                    "status": "completed",
                    "completed_at": datetime.utcnow().isoformat()
                }
            )
        
        return error_response("Failed to complete appointment", 400)
        
    except Exception as e:
        return error_response(str(e), 500)


@appointment_bp.route('/<appointment_id>', methods=['GET'])
@token_required
def get_appointment_details(current_user, appointment_id):
    """
    Get appointment details
    ---
    tags:
      - Appointments
    security:
      - Bearer: []
    parameters:
      - name: appointment_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Appointment details
    """
    try:
        # Get appointment
        query = {"_id": ObjectId(appointment_id)}
        if current_user['role'] == 'patient':
            query['patient_id'] = ObjectId(current_user['_id'])
        elif current_user['role'] == 'doctor':
            query['doctor_id'] = ObjectId(current_user['_id'])
        
        appointment = mongo.db.appointments.find_one(query)
        
        if not appointment:
            return error_response("Appointment not found", 404)
        
        # Get patient details
        patient = mongo.db.users.find_one(
            {"_id": appointment['patient_id']},
            {"password": 0}
        )
        
        # Get doctor details
        doctor = mongo.db.users.find_one(
            {"_id": appointment['doctor_id']},
            {"password": 0}
        )
        
        # Format response
        appointment['_id'] = str(appointment['_id'])
        appointment['patient_id'] = str(appointment['patient_id'])
        appointment['doctor_id'] = str(appointment['doctor_id'])
        appointment['connection_id'] = str(appointment['connection_id'])
        
        appointment['patient'] = {
            "id": str(patient['_id']),
            "name": patient['full_name'],
            "email": patient['email'],
            "phone": patient.get('phone'),
            "age": patient.get('age'),
            "blood_group": patient.get('blood_group'),
            "chronic_conditions": patient.get('chronic_conditions', [])
        } if patient else None
        
        appointment['doctor'] = {
            "id": str(doctor['_id']),
            "name": doctor['full_name'],
            "email": doctor['email'],
            "specialization": doctor.get('specialization'),
            "clinic_address": doctor.get('clinic_address'),
            "mobile_number": doctor.get('mobile_number')
        } if doctor else None
        
        return success_response(
            "Appointment details retrieved",
            {"appointment": appointment}
        )
        
    except Exception as e:
        return error_response(str(e), 500)