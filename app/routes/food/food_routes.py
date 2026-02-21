from flask import Blueprint, request, jsonify
from app.services.food_service import FoodService
from werkzeug.utils import secure_filename
import os

food_bp = Blueprint('food', __name__)
food_service = FoodService()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@food_bp.route('/analyze', methods=['POST'])
def analyze_food():
    """
    Analyze Food Image
    ---
    tags:
      - Food Recognition
    consumes:
      - multipart/form-data
    parameters:
      - name: image
        in: formData
        type: file
        required: true
        description: Food image to analyze
    responses:
      200:
        description: Food analysis results
      400:
        description: No image provided or invalid format
      500:
        description: Server error
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                "success": False,
                "error": "No image file provided"
            }), 400
        
        file = request.files['image']
        
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected"
            }), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                "success": False,
                "error": "Invalid file format. Allowed: png, jpg, jpeg, webp"
            }), 400
        
        # Read image bytes
        image_bytes = file.read()
        
        # Analyze food
        result = food_service.analyze_food_image(image_bytes)
        
        if result.get("success"):
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@food_bp.route('/detect', methods=['POST'])
def detect_food():
    """
    Detect Food Only (No Nutrition)
    ---
    tags:
      - Food Recognition
    consumes:
      - multipart/form-data
    parameters:
      - name: image
        in: formData
        type: file
        required: true
        description: Food image
    responses:
      200:
        description: Food detection results
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                "success": False,
                "error": "No image file provided"
            }), 400
        
        file = request.files['image']
        image_bytes = file.read()
        
        result = food_service.detect_food(image_bytes)
        return jsonify(result), 200 if result.get("success") else 400
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@food_bp.route('/nutrition/<food_name>', methods=['GET'])
def get_nutrition(food_name):
    """
    Get Nutrition Info by Food Name
    ---
    tags:
      - Food Recognition
    parameters:
      - name: food_name
        in: path
        type: string
        required: true
        description: Name of the food
    responses:
      200:
        description: Nutrition information
    """
    try:
        result = food_service.get_nutrition(food_name)
        return jsonify(result), 200 if result.get("success") else 400
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500