from flask_pymongo import PyMongo

mongo = PyMongo()

def init_mongo(app):
    """Initialize and test MongoDB connection"""
    try:
        mongo.init_app(app)
        # Test the connection
        with app.app_context():
            # Ping the database
            mongo.cx.admin.command('ping')
            print("✅ MongoDB Connected Successfully!")
        return True
    except Exception as e:
        print(f"❌ MongoDB Connection Failed: {e}")
        print("Please ensure MongoDB is running: net start MongoDB")
        return False