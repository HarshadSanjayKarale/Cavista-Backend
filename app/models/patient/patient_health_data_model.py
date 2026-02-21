from datetime import datetime
from typing import Optional, Dict

class PatientHealthData:
    """Model for storing patient vitals and health metrics"""
    
    def __init__(self, patient_id: str, data_type: str, value: Dict):
        self.patient_id = patient_id
        self.data_type = data_type  # vitals, activity, sleep, mental_health, etc.
        self.value = value
        self.timestamp = datetime.utcnow()
        self.source = None  # wearable, manual, clinic
        self.notes = None
    
    def to_dict(self):
        return {
            "patient_id": self.patient_id,
            "data_type": self.data_type,
            "value": self.value,
            "timestamp": self.timestamp,
            "source": self.source,
            "notes": self.notes
        }


class VitalsData:
    """Structured vitals data"""
    
    @staticmethod
    def create_vitals(heart_rate: Optional[int] = None,
                     blood_pressure_systolic: Optional[int] = None,
                     blood_pressure_diastolic: Optional[int] = None,
                     blood_glucose: Optional[float] = None,
                     body_temperature: Optional[float] = None,
                     oxygen_saturation: Optional[int] = None,
                     respiratory_rate: Optional[int] = None):
        return {
            "heart_rate": heart_rate,  # bpm
            "blood_pressure": {
                "systolic": blood_pressure_systolic,
                "diastolic": blood_pressure_diastolic
            } if blood_pressure_systolic else None,
            "blood_glucose": blood_glucose,  # mg/dL
            "body_temperature": body_temperature,  # Fahrenheit
            "oxygen_saturation": oxygen_saturation,  # %
            "respiratory_rate": respiratory_rate  # breaths per minute
        }


class ActivityData:
    """Physical activity tracking"""
    
    @staticmethod
    def create_activity(steps: Optional[int] = None,
                       distance: Optional[float] = None,
                       calories_burned: Optional[int] = None,
                       active_minutes: Optional[int] = None,
                       workout_type: Optional[str] = None):
        return {
            "steps": steps,
            "distance": distance,  # km
            "calories_burned": calories_burned,
            "active_minutes": active_minutes,
            "workout_type": workout_type
        }


class SleepData:
    """Sleep pattern tracking"""
    
    @staticmethod
    def create_sleep(duration: Optional[float] = None,
                    quality_score: Optional[int] = None,
                    deep_sleep_hours: Optional[float] = None,
                    rem_sleep_hours: Optional[float] = None,
                    wake_up_count: Optional[int] = None):
        return {
            "duration": duration,  # hours
            "quality_score": quality_score,  # 1-100
            "deep_sleep_hours": deep_sleep_hours,
            "rem_sleep_hours": rem_sleep_hours,
            "wake_up_count": wake_up_count
        }