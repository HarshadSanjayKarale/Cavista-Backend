"""
Mock Wearable Data Routes
For testing without actual wearable device
"""
from flask import Blueprint, jsonify, request
from datetime import datetime, timedelta
from app.routes.wearable.mock_data_generator import MockWearableDataGenerator
from app.models.wearable.wearable_model import WearableData
from bson import ObjectId

mock_bp = Blueprint('mock_wearable', __name__)

# Store active generators for each user
active_generators = {}

@mock_bp.route('/start/<user_id>', methods=['POST'])
def start_mock_data(user_id):
    """
    Start Mock Data Generation
    ---
    tags:
      - Mock Wearable Data
    summary: Start generating mock wearable data for a user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Mock data generation started
    """
    try:
        if user_id not in active_generators:
            active_generators[user_id] = MockWearableDataGenerator(user_id)
        
        # Generate first data point
        data_id, data = active_generators[user_id].save_data_point()
        
        return jsonify({
            'success': True,
            'message': f'Mock data generation started for user {user_id}',
            'data_id': data_id,
            'data': data,
            'note': 'Call /generate endpoint every 1 minute to simulate real-time data'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/generate/<user_id>', methods=['POST'])
def generate_data_point(user_id):
    """
    Generate Single Data Point
    ---
    tags:
      - Mock Wearable Data
    summary: Generate a single mock data point (call every 1 minute)
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Data point generated
    """
    try:
        if user_id not in active_generators:
            active_generators[user_id] = MockWearableDataGenerator(user_id)
        
        data_id, data = active_generators[user_id].save_data_point()
        
        return jsonify({
            'success': True,
            'message': 'Data point generated',
            'data_id': data_id,
            'timestamp': datetime.utcnow().isoformat(),
            'data': data
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/historical/<user_id>', methods=['POST'])
def generate_historical_data(user_id):
    """
    Generate Historical Data
    ---
    tags:
      - Mock Wearable Data
    summary: Generate historical mock data for testing
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
      - name: days
        in: query
        type: integer
        default: 7
        description: Number of days of historical data
    responses:
      200:
        description: Historical data generated
    """
    try:
        days = int(request.args.get('days', 7))
        
        if user_id not in active_generators:
            active_generators[user_id] = MockWearableDataGenerator(user_id)
        
        records_created = active_generators[user_id].generate_historical_data(days)
        
        return jsonify({
            'success': True,
            'message': f'Generated {days} days of historical data',
            'records_created': records_created,
            'user_id': user_id
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/data/<user_id>', methods=['GET'])
def get_user_data(user_id):
    """
    Get User's Wearable Data
    ---
    tags:
      - Mock Wearable Data
    summary: Retrieve user's wearable data
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
      - name: limit
        in: query
        type: integer
        default: 100
        description: Number of records to retrieve
    responses:
      200:
        description: User data retrieved
    """
    try:
        limit = int(request.args.get('limit', 100))
        data = WearableData.get_user_data(user_id, limit)
        
        # Convert ObjectId to string
        for item in data:
            item['_id'] = str(item['_id'])
        
        return jsonify({
            'success': True,
            'count': len(data),
            'data': data
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/data/today/<user_id>', methods=['GET'])
def get_today_data(user_id):
    """
    Get Today's Data
    ---
    tags:
      - Mock Wearable Data
    summary: Get today's wearable data for user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Today's data retrieved
    """
    try:
        data = WearableData.get_today_data(user_id)
        
        # Convert ObjectId to string
        for item in data:
            item['_id'] = str(item['_id'])
        
        # Get latest values
        latest = data[0] if data else None
        
        return jsonify({
            'success': True,
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'count': len(data),
            'latest': latest,
            'data': data
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/data/latest/<user_id>', methods=['GET'])
def get_latest_data(user_id):
    """
    Get Latest Data Point
    ---
    tags:
      - Mock Wearable Data
    summary: Get the most recent data point for user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Latest data retrieved
    """
    try:
        data = WearableData.get_latest_data(user_id)
        
        if data:
            data['_id'] = str(data['_id'])
        
        return jsonify({
            'success': True,
            'data': data
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/stop/<user_id>', methods=['POST'])
def stop_mock_data(user_id):
    """
    Stop Mock Data Generation
    ---
    tags:
      - Mock Wearable Data
    summary: Stop generating mock data for user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Mock data generation stopped
    """
    try:
        if user_id in active_generators:
            del active_generators[user_id]
        
        return jsonify({
            'success': True,
            'message': f'Mock data generation stopped for user {user_id}'
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@mock_bp.route('/clear/<user_id>', methods=['DELETE'])
def clear_user_data(user_id):
    """
    Clear User Data
    ---
    tags:
      - Mock Wearable Data
    summary: Delete all wearable data for user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: User data cleared
    """
    try:
        result = WearableData.delete_user_data(user_id)
        
        return jsonify({
            'success': True,
            'message': f'Deleted {result.deleted_count} records for user {user_id}',
            'deleted_count': result.deleted_count
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500