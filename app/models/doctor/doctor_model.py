from datetime import datetime
from typing import Optional, List

class Doctor:
    def __init__(self, email: str, password: bytes, full_name: str,
                 phone: Optional[str] = None, specialization: Optional[str] = None,
                 license_number: Optional[str] = None, qualification: Optional[str] = None,
                 experience_years: Optional[int] = None, consultation_fee: Optional[float] = None,
                 available_days: Optional[List[str]] = None, available_hours: Optional[str] = None):
        self.email = email
        self.password = password
        self.full_name = full_name
        self.role = "doctor"
        self.phone = phone
        self.specialization = specialization
        self.license_number = license_number
        self.qualification = qualification
        self.experience_years = experience_years
        self.consultation_fee = consultation_fee
        self.available_days = available_days or []
        self.available_hours = available_hours
        
        # Required profile fields (mandatory after signup)
        self.mobile_number = None  # Required
        self.degree = None  # Required (e.g., MBBS, MD)
        self.degree_college = None  # Required
        self.clinic_address = None  # Required
        
        # Additional professional details
        self.registration_year = None
        self.medical_council = None  # e.g., "Medical Council of India"
        self.languages_spoken = []
        self.certifications = []
        
        # Practice details
        self.clinic_name = None
        self.clinic_phone = None
        self.consultation_mode = []  # ["in-person", "video", "phone"]
        self.emergency_available = False
        
        # Specialization details
        self.sub_specializations = []
        self.conditions_treated = []  # List of conditions doctor treats
        self.procedures_performed = []
        
        # Ratings & reviews
        self.rating = 0.0
        self.total_reviews = 0
        self.total_consultations = 0
        
        # System fields
        self.appointments = []
        self.connected_patients = []  # List of patient IDs
        self.pending_connection_requests = []
        self.is_verified = False
        self.is_profile_complete = False
        self.is_active = True
        self.is_accepting_patients = True
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
            "specialization": self.specialization,
            "license_number": self.license_number,
            "qualification": self.qualification,
            "experience_years": self.experience_years,
            "consultation_fee": self.consultation_fee,
            "available_days": self.available_days,
            "available_hours": self.available_hours,
            
            # Required profile fields
            "mobile_number": self.mobile_number,
            "degree": self.degree,
            "degree_college": self.degree_college,
            "clinic_address": self.clinic_address,
            
            # Professional details
            "registration_year": self.registration_year,
            "medical_council": self.medical_council,
            "languages_spoken": self.languages_spoken,
            "certifications": self.certifications,
            
            # Practice details
            "clinic_name": self.clinic_name,
            "clinic_phone": self.clinic_phone,
            "consultation_mode": self.consultation_mode,
            "emergency_available": self.emergency_available,
            
            # Specialization
            "sub_specializations": self.sub_specializations,
            "conditions_treated": self.conditions_treated,
            "procedures_performed": self.procedures_performed,
            
            # Ratings
            "rating": self.rating,
            "total_reviews": self.total_reviews,
            "total_consultations": self.total_consultations,
            
            # System fields
            "appointments": self.appointments,
            "connected_patients": self.connected_patients,
            "pending_connection_requests": self.pending_connection_requests,
            "is_verified": self.is_verified,
            "is_profile_complete": self.is_profile_complete,
            "is_active": self.is_active,
            "is_accepting_patients": self.is_accepting_patients,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login": self.last_login
        }