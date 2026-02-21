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
        self.appointments = []
        self.patients = []
        self.is_verified = False
        self.is_active = True
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
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
            "appointments": self.appointments,
            "patients": self.patients,
            "is_verified": self.is_verified,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }