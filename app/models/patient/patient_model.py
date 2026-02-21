from datetime import datetime
from typing import Optional

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
        self.medical_history = []
        self.appointments = []
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
            "date_of_birth": self.date_of_birth,
            "gender": self.gender,
            "blood_group": self.blood_group,
            "address": self.address,
            "emergency_contact": self.emergency_contact,
            "medical_history": self.medical_history,
            "appointments": self.appointments,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }