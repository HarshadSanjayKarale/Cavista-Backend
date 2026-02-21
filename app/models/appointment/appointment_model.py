from datetime import datetime

class Appointment:
    """
    Appointment Model for Patient-Doctor appointments
    """
    
    def __init__(
        self,
        patient_id,
        doctor_id,
        connection_id,
        appointment_type="consultation",
        reason=None,
        symptoms=None,
        preferred_date=None,
        preferred_time_slot=None,
        notes=None,
        is_urgent=False
    ):
        self.patient_id = patient_id
        self.doctor_id = doctor_id
        self.connection_id = connection_id
        self.appointment_type = appointment_type  # consultation, follow-up, emergency, checkup
        self.reason = reason
        self.symptoms = symptoms if symptoms else []
        self.preferred_date = preferred_date
        self.preferred_time_slot = preferred_time_slot
        self.status = "pending"  # pending, confirmed, rescheduled, completed, cancelled
        self.is_urgent = is_urgent
        
        # Will be set by doctor when confirming
        self.confirmed_date = None
        self.confirmed_time = None
        self.duration_minutes = 30  # default 30 minutes
        self.consultation_mode = None  # in-person, video-call, phone-call
        
        # Additional info
        self.notes = notes  # Patient notes
        self.doctor_notes = None  # Doctor's notes
        self.prescription = None
        self.diagnosis = None
        
        # Rejection info
        self.rejection_reason = None
        
        # Timestamps
        self.requested_at = datetime.utcnow()
        self.confirmed_at = None
        self.completed_at = None
        self.cancelled_at = None
        self.cancelled_by = None  # patient or doctor
        
        # Payment info (optional)
        self.consultation_fee = None
        self.payment_status = "pending"  # pending, paid, refunded
        
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert appointment to dictionary for MongoDB"""
        return {
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "connection_id": self.connection_id,
            "appointment_type": self.appointment_type,
            "reason": self.reason,
            "symptoms": self.symptoms,
            "preferred_date": self.preferred_date,
            "preferred_time_slot": self.preferred_time_slot,
            "status": self.status,
            "is_urgent": self.is_urgent,
            
            "confirmed_date": self.confirmed_date,
            "confirmed_time": self.confirmed_time,
            "duration_minutes": self.duration_minutes,
            "consultation_mode": self.consultation_mode,
            
            "notes": self.notes,
            "doctor_notes": self.doctor_notes,
            "prescription": self.prescription,
            "diagnosis": self.diagnosis,
            
            "rejection_reason": self.rejection_reason,
            
            "requested_at": self.requested_at,
            "confirmed_at": self.confirmed_at,
            "completed_at": self.completed_at,
            "cancelled_at": self.cancelled_at,
            "cancelled_by": self.cancelled_by,
            
            "consultation_fee": self.consultation_fee,
            "payment_status": self.payment_status,
            
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }