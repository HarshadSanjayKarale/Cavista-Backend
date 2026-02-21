"""
Wearable Data Model
Stores health metrics from wearable devices
"""
from datetime import datetime
from app.extensions import mongo

class WearableData:
    """Model for wearable health data"""
    
    collection = mongo.db.wearable_data
    
    @staticmethod
    def create_data(user_id, data):
        """
        Create new wearable data entry
        
        Args:
            user_id: User identifier
            data: Dictionary containing health metrics
        """
        wearable_entry = {
            'user_id': user_id,
            'timestamp': datetime.utcnow(),
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'time': datetime.utcnow().strftime('%H:%M:%S'),
            'steps': data.get('steps', 0),
            'calories': data.get('calories', 0),
            'distance_km': data.get('distance_km', 0.0),
            'sleep_hrs': data.get('sleep_hrs', 0.0),
            'active_min': data.get('active_min', 0),
            'heart_rate': data.get('heart_rate', 0),
            'bmi': data.get('bmi', 0.0),
            'weight_kg': data.get('weight_kg', 0.0),
            'height_cm': data.get('height_cm', 0.0),
            'blood_pressure': {
                'systolic': data.get('systolic', 0),
                'diastolic': data.get('diastolic', 0)
            },
            'oxygen_saturation': data.get('oxygen_saturation', 0),
            'created_at': datetime.utcnow()
        }
        
        result = WearableData.collection.insert_one(wearable_entry)
        return str(result.inserted_id)
    
    @staticmethod
    def get_user_data(user_id, limit=100):
        """Get user's wearable data"""
        return list(WearableData.collection.find(
            {'user_id': user_id}
        ).sort('timestamp', -1).limit(limit))
    
    @staticmethod
    def get_today_data(user_id):
        """Get today's data for user"""
        today = datetime.utcnow().strftime('%Y-%m-%d')
        return list(WearableData.collection.find({
            'user_id': user_id,
            'date': today
        }).sort('timestamp', -1))
    
    @staticmethod
    def get_date_range_data(user_id, start_date, end_date):
        """Get data for date range"""
        return list(WearableData.collection.find({
            'user_id': user_id,
            'date': {
                '$gte': start_date,
                '$lte': end_date
            }
        }).sort('timestamp', -1))
    
    @staticmethod
    def get_latest_data(user_id):
        """Get latest data point for user"""
        return WearableData.collection.find_one(
            {'user_id': user_id},
            sort=[('timestamp', -1)]
        )
    
    @staticmethod
    def delete_user_data(user_id):
        """Delete all data for user"""
        return WearableData.collection.delete_many({'user_id': user_id})