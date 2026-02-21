from datetime import datetime
from typing import Optional, List, Dict

class Patient:
    def __init__(self, email: str, password: bytes, full_name: str, 
                 phone: Optional[str] = None, date_of_birth: Optional[str] = None,
                 gender: Optional[str] = None, blood_group: Optional[str] = None,
                 address: Optional[str] = None, emergency_contact: Optional[str] = None):
        self.email = email
        self.password = password
        self.full_name = full_name
        self.role = "patient"
        self.phone = phone
        self.date_of_birth = date_of_birth
        self.gender = gender
        self.blood_group = blood_group
        self.address = address
        self.emergency_contact = emergency_contact
        
        # Profile completion fields (required after signup)
        self.age = None  # in years
        self.weight = None  # in kg
        self.height = None  # in cm
        self.diet_type = None  # veg, nonveg, vegan
        self.workout_level = None  # Beginner, Intermediate, Advanced
        
        # Health monitoring fields
        self.chronic_conditions = []  # ["Diabetes", "Hypertension", etc.]
        self.allergies = []
        self.current_medications = []
        self.family_medical_history = []
        
        # Wearable & vitals data
        self.wearable_connected = False
        self.wearable_device_id = None
        self.last_vitals = {}  # Latest readings
        
        # Mental health & lifestyle
        self.stress_level = None  # 1-10 scale
        self.sleep_hours_avg = None
        self.smoking_status = None  # never, former, current
        self.alcohol_consumption = None  # none, occasional, regular
        
        # Fall detection & safety (for elderly)
        self.is_elderly = False
        self.fall_detection_enabled = False
        self.emergency_contacts = []  # List of emergency contacts with relationship
        
        # Medication adherence
        self.medication_reminders_enabled = False
        self.medication_schedule = []
        
        # System fields
        self.medical_history = []
        self.appointments = []
        self.connected_doctors = []  # List of doctor IDs
        self.health_reports = []
        self.is_profile_complete = False
        self.is_active = True
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        self.last_login = None
    
    def to_dict(self):
        return {
            "email": self.email,
            "password": self.password,
            "full_name": self.full_name,
            "role": self.role,
            "phone": self.phone,
            "date_of_birth": self.date_of_birth,
            "gender": self.gender,
            "blood_group": self.blood_group,
            "address": self.address,
            "emergency_contact": self.emergency_contact,
            
            # Profile fields
            "age": self.age,
            "weight": self.weight,
            "height": self.height,
            "diet_type": self.diet_type,
            "workout_level": self.workout_level,
            
            # Health monitoring
            "chronic_conditions": self.chronic_conditions,
            "allergies": self.allergies,
            "current_medications": self.current_medications,
            "family_medical_history": self.family_medical_history,
            
            # Wearable data
            "wearable_connected": self.wearable_connected,
            "wearable_device_id": self.wearable_device_id,
            "last_vitals": self.last_vitals,
            
            # Lifestyle
            "stress_level": self.stress_level,
            "sleep_hours_avg": self.sleep_hours_avg,
            "smoking_status": self.smoking_status,
            "alcohol_consumption": self.alcohol_consumption,
            
            # Safety features
            "is_elderly": self.is_elderly,
            "fall_detection_enabled": self.fall_detection_enabled,
            "emergency_contacts": self.emergency_contacts,
            
            # Medication
            "medication_reminders_enabled": self.medication_reminders_enabled,
            "medication_schedule": self.medication_schedule,
            
            # System fields
            "medical_history": self.medical_history,
            "appointments": self.appointments,
            "connected_doctors": self.connected_doctors,
            "health_reports": self.health_reports,
            "is_profile_complete": self.is_profile_complete,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login": self.last_login
        }

class PatientHealthData:
    def __init__(self, patient: Patient, health_data: dict):
        self.patient = patient
        self.health_data = health_data
        self.created_at = datetime.utcnow()
    
    def to_dict(self):
        return {
            "patient": self.patient.to_dict(),
            "health_data": self.health_data,
            "created_at": self.created_at
        }