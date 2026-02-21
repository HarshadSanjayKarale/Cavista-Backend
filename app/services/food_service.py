import requests
import os
from werkzeug.utils import secure_filename

class FoodService:
    def __init__(self):
        self.hf_token = os.getenv("HF_TOKEN")
        self.usda_key = os.getenv("USDA_KEY")
        self.hf_url = "https://router.huggingface.co/hf-inference/models/nateraw/food"
        self.hf_headers = {
            "Authorization": f"Bearer {self.hf_token}",
            "Content-Type": "application/octet-stream"
        }
    
    def detect_food(self, image_bytes):
        """Detect food from image using Hugging Face API"""
        try:
            response = requests.post(
                self.hf_url, 
                headers=self.hf_headers, 
                data=image_bytes,
                timeout=30
            )
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"HuggingFace API error: {response.status_code}",
                    "details": response.text
                }
            
            predictions = response.json()
            
            if isinstance(predictions, list) and len(predictions) > 0:
                return {
                    "success": True,
                    "label": predictions[0]["label"],
                    "confidence": predictions[0]["score"],
                    "all_predictions": predictions[:3]  # Top 3 predictions
                }
            else:
                return {
                    "success": False,
                    "error": "No food detected in image"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_nutrition(self, food_name):
        """Get nutrition info from USDA API"""
        try:
            url = "https://api.nal.usda.gov/fdc/v1/foods/search"
            params = {
                "query": food_name,
                "api_key": self.usda_key,
                "pageSize": 5
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"USDA API error: {response.status_code}",
                    "details": response.text
                }
            
            data = response.json()
            
            if "foods" not in data or len(data["foods"]) == 0:
                return {
                    "success": False,
                    "error": "No nutrition data found for this food"
                }
            
            food = data["foods"][0]
            
            nutrients = {
                "calories": None,
                "protein": None,
                "carbs": None,
                "fat": None,
                "fiber": None,
                "sugar": None,
                "sodium": None
            }
            
            for n in food.get("foodNutrients", []):
                name = n.get("nutrientName", "")
                value = n.get("value", 0)
                unit = n.get("unitName", "")
                
                if "Energy" in name:
                    nutrients["calories"] = {"value": value, "unit": unit}
                elif "Protein" in name:
                    nutrients["protein"] = {"value": value, "unit": unit}
                elif "Carbohydrate" in name:
                    nutrients["carbs"] = {"value": value, "unit": unit}
                elif "Total lipid (fat)" in name or "Fat" in name:
                    nutrients["fat"] = {"value": value, "unit": unit}
                elif "Fiber" in name:
                    nutrients["fiber"] = {"value": value, "unit": unit}
                elif "Sugars" in name:
                    nutrients["sugar"] = {"value": value, "unit": unit}
                elif "Sodium" in name:
                    nutrients["sodium"] = {"value": value, "unit": unit}
            
            return {
                "success": True,
                "food_name": food.get("description", food_name),
                "nutrients": nutrients,
                "serving_size": "per 100g",
                "fdcId": food.get("fdcId"),
                "dataType": food.get("dataType")
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def analyze_food_image(self, image_bytes):
        """Complete food analysis: detection + nutrition"""
        # First, detect the food
        detection_result = self.detect_food(image_bytes)
        
        if not detection_result.get("success"):
            return detection_result
        
        food_label = detection_result["label"]
        
        # Get nutrition info
        nutrition_result = self.get_nutrition(food_label)
        
        return {
            "success": True,
            "detection": {
                "label": food_label,
                "confidence": detection_result["confidence"],
                "alternatives": detection_result.get("all_predictions", [])
            },
            "nutrition": nutrition_result
        }