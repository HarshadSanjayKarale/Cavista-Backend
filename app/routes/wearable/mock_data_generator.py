"""
Mock Wearable Data Generator
Generates realistic health metrics for testing
"""
import random
from datetime import datetime, timedelta
from app.models.wearable.wearable_model import WearableData

class MockWearableDataGenerator:
    """Generate realistic mock wearable data"""
    
    def __init__(self, user_id):
        self.user_id = user_id
        
        # User profile (remains constant)
        self.profile = {
            'height_cm': random.uniform(150, 190),
            'base_weight_kg': random.uniform(50, 100),
            'age': random.randint(20, 60)
        }
        
        # Calculate BMI (remains relatively constant)
        height_m = self.profile['height_cm'] / 100
        self.profile['bmi'] = round(self.profile['base_weight_kg'] / (height_m ** 2), 1)
        
        # Daily cumulative values (reset daily)
        self.daily_totals = {
            'steps': 0,
            'calories': 0,
            'distance_km': 0.0,
            'active_min': 0
        }
        
        # Last update date
        self.last_date = datetime.utcnow().strftime('%Y-%m-%d')
    
    def _reset_daily_totals_if_new_day(self):
        """Reset daily totals if it's a new day"""
        current_date = datetime.utcnow().strftime('%Y-%m-%d')
        if current_date != self.last_date:
            self.daily_totals = {
                'steps': 0,
                'calories': 0,
                'distance_km': 0.0,
                'active_min': 0
            }
            self.last_date = current_date
    
    def generate_data_point(self):
        """Generate a single realistic data point"""
        self._reset_daily_totals_if_new_day()
        
        current_hour = datetime.utcnow().hour
        
        # Steps (cumulative, varies by time of day)
        if 6 <= current_hour <= 22:  # Awake hours
            step_increment = random.randint(50, 200)
        else:  # Sleeping hours
            step_increment = random.randint(0, 20)
        
        self.daily_totals['steps'] += step_increment
        
        # Distance (0.0007 km per step average)
        distance_increment = round(step_increment * 0.0007, 2)
        self.daily_totals['distance_km'] += distance_increment
        
        # Calories (1 calorie per 20 steps + base metabolic rate)
        calories_increment = step_increment // 20 + random.randint(1, 3)
        self.daily_totals['calories'] += calories_increment
        
        # Active minutes (if steps > 100 in this minute)
        if step_increment > 100:
            self.daily_totals['active_min'] += 1
        
        # Heart rate (varies by activity and time)
        if step_increment > 150:  # Active
            heart_rate = random.randint(100, 150)
        elif 6 <= current_hour <= 22:  # Awake, resting
            heart_rate = random.randint(60, 90)
        else:  # Sleeping
            heart_rate = random.randint(50, 70)
        
        # Sleep hours (only meaningful during sleep hours)
        if 22 <= current_hour or current_hour <= 6:
            sleep_hrs = round(random.uniform(0.15, 0.25), 2)  # 9-15 minutes per sample
        else:
            sleep_hrs = 0.0
        
        # Blood pressure (relatively stable)
        systolic = random.randint(110, 130)
        diastolic = random.randint(70, 85)
        
        # Oxygen saturation (stable)
        oxygen_saturation = random.randint(95, 100)
        
        # Weight (minor daily variation)
        weight_kg = round(self.profile['base_weight_kg'] + random.uniform(-0.5, 0.5), 1)
        
        return {
            'steps': self.daily_totals['steps'],
            'calories': self.daily_totals['calories'],
            'distance_km': round(self.daily_totals['distance_km'], 2),
            'sleep_hrs': sleep_hrs,
            'active_min': self.daily_totals['active_min'],
            'heart_rate': heart_rate,
            'bmi': self.profile['bmi'],
            'weight_kg': weight_kg,
            'height_cm': self.profile['height_cm'],
            'systolic': systolic,
            'diastolic': diastolic,
            'oxygen_saturation': oxygen_saturation
        }
    
    def save_data_point(self):
        """Generate and save a data point to database"""
        data = self.generate_data_point()
        data_id = WearableData.create_data(self.user_id, data)
        return data_id, data
    
    def generate_historical_data(self, days=7):
        """Generate historical data for testing"""
        print(f"Generating {days} days of historical data for user {self.user_id}...")
        
        records_created = 0
        for day in range(days, 0, -1):
            # Reset for each day
            self.daily_totals = {
                'steps': 0,
                'calories': 0,
                'distance_km': 0.0,
                'active_min': 0
            }
            
            # Generate data points throughout the day (every 30 minutes = 48 points per day)
            for hour in range(24):
                for minute in [0, 30]:
                    data = self.generate_data_point()
                    
                    # Override timestamp for historical data
                    past_time = datetime.utcnow() - timedelta(days=day, hours=(23-hour), minutes=(60-minute))
                    
                    wearable_entry = {
                        'user_id': self.user_id,
                        'timestamp': past_time,
                        'date': past_time.strftime('%Y-%m-%d'),
                        'time': past_time.strftime('%H:%M:%S'),
                        **data,
                        'blood_pressure': {
                            'systolic': data['systolic'],
                            'diastolic': data['diastolic']
                        },
                        'created_at': past_time
                    }
                    
                    WearableData.collection.insert_one(wearable_entry)
                    records_created += 1
        
        print(f"✅ Generated {records_created} historical data points")
        return records_created