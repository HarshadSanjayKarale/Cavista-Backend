from datetime import datetime
from typing import Optional, List, Dict

class MedicationPrescription:
    """Model for doctor's medication prescription"""
    
    def __init__(self, doctor_id: str, patient_id: str, prescribed_by_name: str):
        self.doctor_id = doctor_id
        self.patient_id = patient_id
        self.prescribed_by_name = prescribed_by_name
        self.prescription_date = datetime.utcnow()
        
        # Medication schedule
        self.morning_medicines = []  # List of medicines for morning
        self.afternoon_medicines = []  # List of medicines for afternoon
        self.evening_medicines = []  # List of medicines for evening
        
        # Additional prescription details
        self.diagnosis = None
        self.notes = None
        self.prescription_duration_days = 30  # Default 30 days
        self.is_active = True
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def to_dict(self):
        return {
            "doctor_id": self.doctor_id,
            "patient_id": self.patient_id,
            "prescribed_by_name": self.prescribed_by_name,
            "prescription_date": self.prescription_date,
            "morning_medicines": self.morning_medicines,
            "afternoon_medicines": self.afternoon_medicines,
            "evening_medicines": self.evening_medicines,
            "diagnosis": self.diagnosis,
            "notes": self.notes,
            "prescription_duration_days": self.prescription_duration_days,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }


class MedicationItem:
    """Individual medication item structure"""
    
    @staticmethod
    def create_medicine(name: str, dosage: str, timing: str, 
                       before_after_food: str, frequency: str = "daily",
                       special_instructions: Optional[str] = None):
        """
        Create a medication item
        
        Args:
            name: Medicine name (e.g., "Paracetamol")
            dosage: Dosage (e.g., "500mg", "1 tablet")
            timing: morning/afternoon/evening
            before_after_food: "before" or "after"
            frequency: "daily", "alternate", "weekly", etc.
            special_instructions: Any special notes
        """
        return {
            "name": name,
            "dosage": dosage,
            "timing": timing,
            "before_after_food": before_after_food,
            "frequency": frequency,
            "special_instructions": special_instructions,
            "added_at": datetime.utcnow()
        }