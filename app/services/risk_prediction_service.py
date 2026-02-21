"""
Risk Prediction Service
Integrates ML model with wearable data
"""
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from app.models.wearable.wearable_model import WearableData

class RiskPredictionService:
    """Service for health risk prediction using ML model"""
    
    def __init__(self):
        # Load the model
        model_path = Path(__file__).parent.parent.parent / "fitness_risk_engine_model.pkl"
        try:
            model_package = joblib.load(model_path)
            self.model = model_package['model']
            self.explainer = model_package['explainer']
            self.features = model_package['features']
            self.version = model_package.get('version', 'N/A')
            print(f"✅ Risk model loaded successfully (version: {self.version})")
        except Exception as e:
            print(f"❌ Error loading risk model: {e}")
            raise
    
    def compute_derived_features(self, df):
        """Compute derived features exactly as in training"""
        df = df.copy()
        
        # Constants (same as training)
        height_m = 1.70
        age_assumed = 38
        stride_m = 0.75
        
        # Convert all columns to float to avoid type issues
        numeric_cols = ['steps', 'calories', 'distance_km', 'sleep_hrs', 'active_min', 'heart_rate', 'bmi']
        for col in numeric_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(float)
        
        # Derived calculations
        weight_kg = df['bmi'] * (height_m ** 2)
        active_hrs = df['active_min'] / 60.0
        speed_kmh = np.where(active_hrs > 0.05, df['distance_km'] / active_hrs, 4.0)
        
        met = np.where(speed_kmh < 5.5, 3.8,
                       np.where(speed_kmh < 8.0, 6.5, 8.0))
        
        df['calories_adjusted'] = (df['steps'] * stride_m * 0.5) + \
                                  (met * df['active_min'] * 3.5 * weight_kg / 200)
        
        df['dist_valid_km'] = (df['steps'] * 0.75) / 1000
        df['dist_error_pct'] = np.where(df['distance_km'] > 0.05,
                                        np.abs(df['distance_km'] - df['dist_valid_km']) / df['distance_km'] * 100,
                                        0.0)
        
        active_evening_proxy = 0.25 * df['active_min']
        hr_night_proxy = df['heart_rate']
        disruption_factor = np.clip(1 - active_evening_proxy / 60, 0.4, 1.0)
        hr_factor = np.where(hr_night_proxy < 65, 1.1, 0.9)
        df['sleep_score'] = 100 * (df['sleep_hrs'] / 8) * disruption_factor * hr_factor
        df['sleep_score'] = df['sleep_score'].clip(0, 100)
        
        df['bmi_proxy'] = (df['bmi']
                           - 0.5 * (df['heart_rate'] - 60)
                           - 0.001 * (df['steps'] / 1000)
                           + (df['calories'] / 2000 * 0.5))
        
        df['health_score'] = (20 * (df['steps'] / 15000) +
                              20 * (df['calories'] / 2500) +
                              15 * (df['sleep_hrs'] / 8) +
                              15 * (df['active_min'] / 60) +
                              15 * (70 / df['heart_rate']) +
                              15 * (25 / df['bmi'])).clip(0, 100)
        
        df['cardiac_csr'] = (15 * (df['active_min'] / 60) +
                             20 * (df['steps'] / 10000) -
                             0.3 * df['bmi'] +
                             10 * np.where(active_hrs > 0, df['distance_km'] / active_hrs, 0) -
                             0.2 * df['heart_rate'] +
                             18)
        
        # Fix the diabetic_csr calculation - convert booleans to integers properly
        bmi_factor = (df['bmi'] > 30).astype(int)
        steps_factor = (df['steps'] < 5000).astype(int)
        hr_factor = (df['heart_rate'] > 80).astype(int)
        sleep_factor = (df['sleep_hrs'] < 6).astype(int)
        cal_factor = (df['calories'] < 1800).astype(int)
        age_factor = int(age_assumed > 50)
        
        df['diabetic_csr'] = 100 - (
            25 * bmi_factor +
            20 * steps_factor +
            20 * hr_factor +
            15 * sleep_factor +
            10 * cal_factor +
            10 * age_factor
        )
        df['diabetic_csr'] = df['diabetic_csr'].clip(0, 100)
        
        return df
    
    def prepare_data_from_db(self, user_id):
        """Fetch and prepare user data from database"""
        # Get latest data point for user
        latest_data = WearableData.get_latest_data(user_id)
        
        if not latest_data:
            raise ValueError(f"No wearable data found for user {user_id}")
        
        # Convert to DataFrame with correct column names
        data_dict = {
            'user_id': [user_id],
            'steps': [float(latest_data.get('steps', 0))],
            'calories': [float(latest_data.get('calories', 0))],
            'distance_km': [float(latest_data.get('distance_km', 0.0))],
            'sleep_hrs': [float(latest_data.get('sleep_hrs', 0.0))],
            'active_min': [float(latest_data.get('active_min', 0))],
            'heart_rate': [float(latest_data.get('heart_rate', 70))],
            'bmi': [float(latest_data.get('bmi', 25.0))]
        }
        
        return pd.DataFrame(data_dict)
    
    def get_risk_class(self, risk_prob):
        """Classify risk level based on probability"""
        if risk_prob <= 0.25:
            return 'Low'
        elif risk_prob <= 0.50:
            return 'Moderate'
        elif risk_prob <= 0.75:
            return 'High'
        else:
            return 'Critical'
    
    def predict_risk(self, user_id):
        """
        Complete risk prediction pipeline for a user
        Returns comprehensive risk assessment
        """
        try:
            # 1. Fetch user data from database
            df = self.prepare_data_from_db(user_id)
            
            # 2. Compute derived features
            df_enriched = self.compute_derived_features(df)
            
            # 3. Prepare features for model - ensure all are float type
            X = df_enriched[self.features].astype(float)
            
            # 4. Predict risk
            risk_prob = float(self.model.predict(X)[0])
            risk_class = self.get_risk_class(risk_prob)
            
            # 5. Get SHAP values for explainability
            shap_values = self.explainer.shap_values(X)
            shap_dict = {
                feat: float(val) 
                for feat, val in zip(self.features, shap_values[0])
            }
            
            # Sort by absolute contribution
            top_factors = sorted(
                shap_dict.items(), 
                key=lambda x: abs(x[1]), 
                reverse=True
            )[:5]
            
            # 6. Build comprehensive response
            result = {
                'user_id': user_id,
                'risk_assessment': {
                    'risk_probability': round(risk_prob, 4),
                    'risk_percentage': round(risk_prob * 100, 2),
                    'risk_class': risk_class,
                    'assessment_date': str(df_enriched.get('timestamp', [None])[0])
                },
                'health_metrics': {
                    'steps': int(df_enriched['steps'].iloc[0]),
                    'calories': int(df_enriched['calories'].iloc[0]),
                    'distance_km': round(float(df_enriched['distance_km'].iloc[0]), 2),
                    'sleep_hrs': round(float(df_enriched['sleep_hrs'].iloc[0]), 2),
                    'active_min': int(df_enriched['active_min'].iloc[0]),
                    'heart_rate': int(df_enriched['heart_rate'].iloc[0]),
                    'bmi': round(float(df_enriched['bmi'].iloc[0]), 1)
                },
                'derived_scores': {
                    'health_score': round(float(df_enriched['health_score'].iloc[0]), 2),
                    'cardiac_csr': round(float(df_enriched['cardiac_csr'].iloc[0]), 2),
                    'diabetic_csr': round(float(df_enriched['diabetic_csr'].iloc[0]), 2),
                    'sleep_score': round(float(df_enriched['sleep_score'].iloc[0]), 2)
                },
                'risk_factors': {
                    'top_contributing_factors': [
                        {
                            'feature': feat,
                            'contribution': round(val, 4),
                            'impact': 'Increases Risk' if val > 0 else 'Decreases Risk'
                        }
                        for feat, val in top_factors
                    ],
                    'all_contributions': shap_dict
                },
                'recommendations': self._generate_recommendations(risk_class, df_enriched, shap_dict)
            }
            
            return result
            
        except Exception as e:
            print(f"❌ Error in predict_risk: {str(e)}")
            import traceback
            traceback.print_exc()
            raise
    
    def _generate_recommendations(self, risk_class, df, shap_values):
        """Generate personalized recommendations based on risk factors"""
        recommendations = []
        
        row = df.iloc[0]
        
        # Step-based recommendations
        if row['steps'] < 5000:
            recommendations.append({
                'category': 'Physical Activity',
                'priority': 'High',
                'message': 'Your daily step count is low. Aim for at least 10,000 steps per day.',
                'action': 'Increase daily walking or add a 30-minute walk to your routine.'
            })
        
        # Sleep recommendations
        if row['sleep_hrs'] < 6:
            recommendations.append({
                'category': 'Sleep',
                'priority': 'High',
                'message': 'Inadequate sleep detected. Aim for 7-8 hours per night.',
                'action': 'Establish a consistent sleep schedule and avoid screens before bed.'
            })
        
        # BMI recommendations
        if row['bmi'] > 30:
            recommendations.append({
                'category': 'Body Composition',
                'priority': 'High',
                'message': 'BMI indicates obesity. Consider weight management.',
                'action': 'Consult with a healthcare provider for a personalized weight loss plan.'
            })
        elif row['bmi'] > 25:
            recommendations.append({
                'category': 'Body Composition',
                'priority': 'Medium',
                'message': 'BMI indicates overweight. Small lifestyle changes can help.',
                'action': 'Focus on balanced nutrition and regular exercise.'
            })
        
        # Heart rate recommendations
        if row['heart_rate'] > 80:
            recommendations.append({
                'category': 'Cardiovascular',
                'priority': 'Medium',
                'message': 'Elevated resting heart rate detected.',
                'action': 'Incorporate cardio exercises and stress management techniques.'
            })
        
        # Active minutes
        if row['active_min'] < 30:
            recommendations.append({
                'category': 'Physical Activity',
                'priority': 'Medium',
                'message': 'Low active minutes. WHO recommends 150 minutes/week.',
                'action': 'Add moderate-intensity exercise like brisk walking or cycling.'
            })
        
        # General recommendation based on risk class
        if risk_class == 'Critical':
            recommendations.insert(0, {
                'category': 'Urgent',
                'priority': 'Critical',
                'message': 'Critical risk level detected. Immediate action recommended.',
                'action': 'Schedule a health check-up with your physician as soon as possible.'
            })
        elif risk_class == 'High':
            recommendations.insert(0, {
                'category': 'Important',
                'priority': 'High',
                'message': 'High risk level. Proactive health management needed.',
                'action': 'Consider scheduling a general health assessment.'
            })
        
        return recommendations

# Singleton instance
risk_service = RiskPredictionService()