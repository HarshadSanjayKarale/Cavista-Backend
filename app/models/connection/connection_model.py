from datetime import datetime
from typing import Optional

class Connection:
    """Model for patient-doctor connections"""
    
    def __init__(self, patient_id: str, doctor_id: str, 
                 request_initiated_by: str = "patient"):
        self.patient_id = patient_id
        self.doctor_id = doctor_id
        self.status = "pending"  # pending, active, rejected, inactive
        self.request_initiated_by = request_initiated_by  # patient or doctor
        self.requested_at = datetime.utcnow()
        self.approved_at = None
        self.rejected_at = None
        self.rejection_reason = None
        
        # Connection details
        self.primary_doctor = False  # Is this the patient's primary doctor
        self.connection_reason = None  # Why patient wants to connect
        self.conditions_being_treated = []  # List of conditions
        
        # Communication preferences
        self.allow_vitals_sharing = True
        self.allow_medication_access = True
        self.allow_emergency_contact = True
        self.notification_preferences = {
            "vitals_alerts": True,
            "appointment_reminders": True,
            "medication_reminders": True
        }
        
        # Activity tracking
        self.last_consultation = None
        self.total_consultations = 0
        self.last_interaction = None
        
        # Notes
        self.doctor_notes = []  # Private notes by doctor
        self.shared_notes = []  # Notes visible to both
        
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def to_dict(self):
        return {
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "status": self.status,
            "request_initiated_by": self.request_initiated_by,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "rejected_at": self.rejected_at,
            "rejection_reason": self.rejection_reason,
            
            "primary_doctor": self.primary_doctor,
            "connection_reason": self.connection_reason,
            "conditions_being_treated": self.conditions_being_treated,
            
            "allow_vitals_sharing": self.allow_vitals_sharing,
            "allow_medication_access": self.allow_medication_access,
            "allow_emergency_contact": self.allow_emergency_contact,
            "notification_preferences": self.notification_preferences,
            
            "last_consultation": self.last_consultation,
            "total_consultations": self.total_consultations,
            "last_interaction": self.last_interaction,
            
            "doctor_notes": self.doctor_notes,
            "shared_notes": self.shared_notes,
            
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }