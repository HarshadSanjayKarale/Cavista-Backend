from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import os
from dotenv import load_dotenv
from bson import ObjectId

# Load environment variables
load_dotenv()

app = Flask(__name__)

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

# MongoDB Configuration
# MongoDB Configuration
client = MongoClient(os.getenv('MONGODB_URI', 'mongodb://localhost:27017/'))
db = client['auth_db']
users_collection = db['users']
blacklist_collection = db['token_blacklist']
posts_collection = db['posts']

# Add the new routes here

# Helper function to validate email format
def is_valid_email(email):
    import re
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

@app.route('/api/auth/register/doctor', methods=['POST'])
def register_doctor():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(k in data for k in ('username', 'email', 'mobno', 'password', 'verification_id')):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate email format
        if not is_valid_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if email already exists
        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 409
        
        # Validate password strength (minimum 8 characters)
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Create new doctor
        new_doctor = {
            'username': data['username'],
            'email': data['email'],
            'mobno': data['mobno'],
            'password': generate_password_hash(data['password']),
            'verification_id': data['verification_id'],
            'role': 'doctor',
            'created_at': datetime.utcnow()
        }
        
        result = users_collection.insert_one(new_doctor)
        
        return jsonify({
            'message': 'Doctor registered successfully',
            'user_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/register/patient', methods=['POST'])
def register_patient():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(k in data for k in ('username', 'email', 'mobno', 'password')):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Validate email format
        if not is_valid_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if email already exists
        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 409
        
        # Validate password strength (minimum 8 characters)
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Create new patient
        new_patient = {
            'username': data['username'],
            'email': data['email'],
            'mobno': data['mobno'],
            'password': generate_password_hash(data['password']),
            'role': 'patient',
            'created_at': datetime.utcnow()
        }
        
        result = users_collection.insert_one(new_patient)
        
        return jsonify({
            'message': 'Patient registered successfully',
            'user_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validate required fields
        if not all(k in data for k in ('email', 'password')):
            return jsonify({'error': 'Missing email or password'}), 400
        
        # Find user
        user = users_collection.find_one({'email': data['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Verify password
        if not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid password'}), 401
        
        # Generate tokens
        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': str(user['_id']),
                'email': user['email'],
                'username': user['username']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        current_user_id = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': new_access_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()['jti']
        blacklist_collection.insert_one({
            'jti': jti,
            'created_at': datetime.utcnow()
        })
        
        return jsonify({
            'message': 'Successfully logged out'
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        current_user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': str(user['_id']),
            'email': user['email'],
            'username': user['username']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/users/<user_id>', methods=['GET'])
@jwt_required()
def get_user_by_id(user_id):
    try:
        # Validate object ID format
        if not ObjectId.is_valid(user_id):
            return jsonify({'error': 'Invalid user ID format'}), 400
            
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'id': str(user['_id']),
            'email': user['email'],
            'username': user['username'],
            'created_at': user['created_at'].isoformat() if 'created_at' in user else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

# Token blacklist checker
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return blacklist_collection.find_one({'jti': jti}) is not None


#Post API Started here
@app.route('/api/posts', methods=['POST'])
@jwt_required()
def add_post():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()

        new_post = {
            'content': data['content'],
            'authorId': current_user_id,
            'authorName': data['authorName'],
            'images': data.get('images', []),
            'comments': [],
            'verifiedCount': 0,
            'verifiedBy': [],
            'createdAt': datetime.utcnow()
        }

        result = posts_collection.insert_one(new_post)
        return jsonify({'message': 'Post added successfully', 'post_id': str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/posts/<post_id>', methods=['PUT'])
@jwt_required()
def edit_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        if post['authorId'] != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        posts_collection.update_one(
            {'_id': ObjectId(post_id)},
            {'$set': {'content': data['content'], 'images': data.get('images', post['images'])}}
        )
        
        return jsonify({'message': 'Post updated successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/posts/<post_id>', methods=['DELETE'])
@jwt_required()
def delete_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        
        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        if post['authorId'] != current_user_id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        posts_collection.delete_one({'_id': ObjectId(post_id)})
        return jsonify({'message': 'Post deleted successfully'}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/posts', methods=['GET'])
@jwt_required()
def get_all_posts():
    try:
        posts = list(posts_collection.find())
        for post in posts:
            post['_id'] = str(post['_id'])
        return jsonify(posts), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
