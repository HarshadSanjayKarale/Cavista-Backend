from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger
from app.config import Config
from app.extensions import mongo, init_mongo

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
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
            "title": "Cavista Hackathon 2026 API",
            "description": "Interactive Authentication API with JWT",
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
    
    # Register blueprints
    from app.routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    
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
        # Check MongoDB connection
        mongo_status = "connected"
        try:
            mongo.cx.admin.command('ping')
        except:
            mongo_status = "disconnected"
        
        return jsonify({
            "message": "API is running",
            "docs": "/apidocs",
            "mongodb": mongo_status
        }), 200
    
    # Error handler for MongoDB connection issues
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