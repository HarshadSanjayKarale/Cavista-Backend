from flask import Flask, jsonify
from flask_cors import CORS
from flask_session import Session
from flasgger import Swagger
from app.config import Config
from app.extensions import mongo, init_mongo

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize Flask-Session (for Google Fit OAuth)
    Session(app)
    
    # Initialize MongoDB
    mongo_connected = init_mongo(app)
    
    if not mongo_connected:
        print("\n" + "="*60)
        print("⚠️  WARNING: MongoDB is not connected!")
        print("="*60)
        print("Quick Fix:")
        print("1. Start MongoDB: net start MongoDB")
        print("2. Or install MongoDB from: https://www.mongodb.com/try/download/community")
        print("3. Or use Docker: docker run -d -p 27017:27017 mongo")
        print("="*60 + "\n")
    
    # Configure CORS
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Swagger configuration
    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/apidocs/",
        "swagger_ui_config": {
            "persistAuthorization": True,
            "displayRequestDuration": True,
            "filter": True,
            "tryItOutEnabled": True
        }
    }
    
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "AI-Driven Preventive Health Companion API",
            "description": "Healthcare platform connecting patients and doctors with AI-powered health monitoring",
            "version": "1.0.0"
        },
        "host": "localhost:5000",
        "basePath": "/",
        "schemes": ["http"],
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header. Example: 'Bearer {token}'"
            }
        }
    }
    
    Swagger(app, config=swagger_config, template=swagger_template)
    
    # Register blueprints - Patient Routes
    from app.routes.patient.patient_routes import patient_bp
    app.register_blueprint(patient_bp, url_prefix='/api/patient')
    
    # Register blueprints - Doctor Routes
    from app.routes.doctor.doctor_routes import doctor_bp
    app.register_blueprint(doctor_bp, url_prefix='/api/doctor')
    
    # Register blueprints - Connection Routes
    from app.routes.connection.connection_routes import connection_bp
    app.register_blueprint(connection_bp, url_prefix='/api/connection')
    
    # Register blueprints - Appointment Routes
    from app.routes.appointment.appointment_routes import appointment_bp
    app.register_blueprint(appointment_bp, url_prefix='/api/appointment')
    
    # Register blueprints - Notification Routes
    from app.routes.notification.notification_routes import notification_bp
    app.register_blueprint(notification_bp, url_prefix='/api/notification')
    
    # Register blueprints - Wearable Routes
    from app.routes.wearable.wearable_routes import wearable_bp
    app.register_blueprint(wearable_bp, url_prefix='/api/wearable')
    
    # Register blueprints - Mock Wearable Routes (for testing)
    from app.routes.wearable.mock_routes import mock_bp
    app.register_blueprint(mock_bp, url_prefix='/api/mock/wearable')
    
    # Register blueprints - Food Recognition Routes
    from app.routes.food.food_routes import food_bp
    app.register_blueprint(food_bp, url_prefix='/api/food')
    
    # Register blueprints - Risk Assessment Routes
    from app.routes.risk.risk_routes import risk_bp
    app.register_blueprint(risk_bp, url_prefix='/api/risk')
    
    @app.route('/', methods=['GET'])
    def health_check():
        """
        Health Check
        ---
        tags:
          - Health
        responses:
          200:
            description: API is running
        """
        mongo_status = "connected"
        try:
            mongo.cx.admin.command('ping')
        except:
            mongo_status = "disconnected"
        
        return jsonify({
            "message": "AI-Driven Preventive Health Companion API is running",
            "docs": "/apidocs",
            "mongodb": mongo_status,
            "endpoints": {
                "patient": "/api/patient",
                "doctor": "/api/doctor",
                "connection": "/api/connection",
                "appointment": "/api/appointment",
                "notification": "/api/notification",
                "wearable": "/api/wearable",
                "food": "/api/food",
                "risk": "/api/risk"
            },
            "features": [
                "Patient-Doctor Connection Management",
                "Wearable Integration",
                "AI-Powered Health Analytics",
                "ML-Based Risk Prediction",
                "Medication Reminders",
                "Fall Detection (Elderly Care)",
                "Virtual Health Assistant",
                "Google Fit Integration"
            ]
        }), 200
    
    @app.errorhandler(Exception)
    def handle_exception(e):
        if "NoneType" in str(e) or "mongo" in str(e).lower():
            return jsonify({
                "success": False,
                "error": "Database connection failed. Please ensure MongoDB is running.",
                "solution": "Run: net start MongoDB"
            }), 503
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500
    
    return app