from flask import Flask, request, jsonify,render_template
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import os
from dotenv import load_dotenv
from bson import ObjectId
import joblib

import numpy as np
import logging
from models import Comment, Reply
from pathlib import Path

load_dotenv()

app = Flask(__name__)


app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

#Database Connection
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("MONGODB_URI is not set in environment variables")

client = MongoClient(MONGODB_URI)
db = client['auth_db']
users_collection = db['users']
blacklist_collection = db['token_blacklist']
posts_collection = db['posts']
comments_collection = db['comments']
notifications_collection = db['notifications']


def is_valid_email(email):
    import re
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None
#Docter Registration
@app.route('/api/auth/register/doctor', methods=['POST'])
def register_doctor():
    try:
        data = request.get_json()
        
        if not all(k in data for k in ('username', 'email', 'mobno', 'password', 'verification_id')):
            return jsonify({'error': 'Missing required fields'}), 400
        
        if not is_valid_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400

        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 409
        
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
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

#Patient Registration
@app.route('/api/auth/register/patient', methods=['POST'])
def register_patient():
    try:
        data = request.get_json()
        

        if not all(k in data for k in ('username', 'email', 'mobno', 'password')):
            return jsonify({'error': 'Missing required fields'}), 400

        if not is_valid_email(data['email']):
            return jsonify({'error': 'Invalid email format'}), 400

        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'Email already registered'}), 409

        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
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

        if not all(k in data for k in ('email', 'password')):
            return jsonify({'error': 'Missing email or password'}), 400

        user = users_collection.find_one({'email': data['email']})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid password'}), 401

        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user': {
                'id': str(user['_id']),
                'email': user['email'],
                'username': user['username'],
                'mobno': user['mobno'],
                'role': user['role']
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
    
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return blacklist_collection.find_one({'jti': jti}) is not None

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

@app.route('/api/posts/<post_id>/add_verifier', methods=['PUT'])
@jwt_required()
def add_verifier(post_id):
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        verifier_id = data['verifier_id']
        verifier_name = data['verifier_name']

        verifier = users_collection.find_one({'_id': ObjectId(verifier_id)})
        if not verifier:
            return jsonify({'error': 'Verifier not found'}), 404
        
        if verifier.get('role') != 'doctor':
            return jsonify({'error': 'Only doctors can verify posts'}), 403

        post = posts_collection.find_one({'_id': ObjectId(post_id)})
        if not post:
            return jsonify({'error': 'Post not found'}), 404

        if not any(v['verifier_id'] == verifier_id for v in post['verifiedBy']):
            verifier_info = {
                'verifier_id': verifier_id, 
                'verifier_name': verifier_name,
                'verified_at': datetime.utcnow()
            }
            
            posts_collection.update_one(
                {'_id': ObjectId(post_id)},
                {
                    '$push': {'verifiedBy': verifier_info},
                    '$inc': {'verifiedCount': 1}
                }
            )
            return jsonify({'message': 'Post verified successfully'}), 200
        else:
            return jsonify({'message': 'Post already verified by this doctor'}), 400

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
    
from bson import ObjectId

@app.route('/api/comments', methods=['POST'])
@jwt_required()
def add_comment():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()

        new_comment = {
            'post_id': data['post_id'],
            'user_id': current_user_id,
            'username': data['username'],
            'content': data['content'],
            'replies': [],
            'created_at': datetime.utcnow()
        }

        result = comments_collection.insert_one(new_comment)
        return jsonify({'message': 'Comment added successfully', 'comment_id': str(result.inserted_id)}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/comments/<comment_id>/reply', methods=['POST'])
@jwt_required()
def reply_to_comment(comment_id):
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()

        reply = {
            'user_id': current_user_id,
            'username': data['username'],
            'content': data['content'],
            'created_at': datetime.utcnow()
        }

        comments_collection.update_one(
            {'_id': ObjectId(comment_id)},
            {'$push': {'replies': reply}}
        )

        return jsonify({'message': 'Reply added successfully'}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/comments/<post_id>', methods=['GET'])
def get_comments(post_id):
    try:
        comments = list(comments_collection.find({'post_id': post_id}))
        
        formatted_comments = []
        for comment in comments:
            formatted_comment = {
                'id': str(comment['_id']),
                'post_id': comment['post_id'],
                'user_id': comment['user_id'],
                'username': comment['username'],
                'content': comment['content'],
                'created_at': comment['created_at'].isoformat() if 'created_at' in comment else None,
                'replies': []
            }

            if 'replies' in comment and comment['replies']:
                for reply in comment['replies']:
                    formatted_reply = {
                        'user_id': reply['user_id'],
                        'username': reply['username'],
                        'content': reply['content'],
                        'created_at': reply['created_at'].isoformat() if 'created_at' in reply else None
                    }
                    formatted_comment['replies'].append(formatted_reply)
            
            formatted_comments.append(formatted_comment)
        
        return jsonify({
            'success': True,
            'comments': formatted_comments,
            'total_comments': len(formatted_comments)
        }), 200

    except Exception as e:
        print(f"Error in get_comments: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    

# List of all doctors
@app.route('/api/doctors', methods=['GET'])
def get_all_doctors():
    try:
        doctors = users_collection.find({'role': 'doctor'}, {'_id': 1, 'username': 1})
        doctor_list = [{'id': str(doctor['_id']), 'name': doctor['username']} for doctor in doctors]

        return jsonify(doctor_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
#Notification will start here
# API to create a notification for appointment request
@app.route('/api/notifications/patient', methods=['POST'])

def create_patient_notification():
    try:
        data = request.get_json()
        notification = {
            'patient_id': ObjectId(data['patient_id']),
            'doctor_id': ObjectId(data['doctor_id']),
            'message': data['message'],
            'notification_type': 'appointment_request',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        notification_id = notifications_collection.insert_one(notification).inserted_id
        return jsonify({"status": "success", "notification_id": str(notification_id)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API to create a notification for appointment response
@app.route('/api/notifications/doctor', methods=['POST'])

def create_doctor_notification():
    try:
        data = request.get_json()
        notification = {
            'patient_id': ObjectId(data['patient_id']),
            'doctor_id': ObjectId(data['doctor_id']),
            'message': data['message'],
            'expected_date': data['expected_date'],
            'expected_time': data['expected_time'],
            'notification_type': 'appointment_response',
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        notification_id = notifications_collection.insert_one(notification).inserted_id
        return jsonify({"status": "success", "notification_id": str(notification_id)}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API to fetch notifications for a patient
@app.route('/api/notifications/patient/<patient_id>', methods=['GET'])

def get_patient_notifications(patient_id):
    try:
        notifications = list(notifications_collection.find({"patient_id": ObjectId(patient_id)}))
        for notification in notifications:
            notification['_id'] = str(notification['_id'])
        return jsonify({"status": "success", "notifications": notifications}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# API to fetch notifications for a doctor
@app.route('/api/notifications/doctor/<doctor_id>', methods=['GET'])
def get_doctor_notifications(doctor_id):
    try:
        notifications = list(notifications_collection.find({"doctor_id": ObjectId(doctor_id)}))
        for notification in notifications:
            notification['_id'] = str(notification['_id'])
        return jsonify({"status": "success", "notifications": notifications}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
