"""
Wearable/Google Fit Integration Routes
Endpoints for OAuth authentication and health data retrieval
"""
import os
from datetime import datetime
from flask import Blueprint, redirect, request, jsonify, session
from flasgger import swag_from
import requests
from app.routes.wearable.oauth_utils import (
    get_google_auth_url,
    exchange_code_for_tokens,
    require_google_auth,
    get_authorized_headers,
    GOOGLE_FIT_API
)

wearable_bp = Blueprint('wearable', __name__)

# ========== Authentication Endpoints ==========

@wearable_bp.route('/auth/google', methods=['GET'])
def auth_google():
    """
    Initiate Google Fit OAuth Flow
    ---
    tags:
      - Wearable Integration
    summary: Initiate Google OAuth authentication
    description: Redirects to Google OAuth consent screen for Google Fit data access
    responses:
      302:
        description: Redirect to Google OAuth page
    """
    auth_url = get_google_auth_url()
    return redirect(auth_url)

@wearable_bp.route('/auth/google/callback', methods=['GET'])
def auth_google_callback():
    """
    Google OAuth Callback
    ---
    tags:
      - Wearable Integration
    summary: Handle Google OAuth callback
    description: Exchanges authorization code for tokens
    parameters:
      - name: code
        in: query
        type: string
        required: true
        description: Authorization code from Google
    responses:
      302:
        description: Redirect to frontend with auth status
    """
    code = request.args.get('code')
    
    if not code:
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}?error=no_code")
    
    try:
        # Exchange authorization code for tokens
        data = exchange_code_for_tokens(code)
        
        # Store tokens in session
        session['access_token'] = data['access_token']
        session['refresh_token'] = data.get('refresh_token')
        session['token_expiry'] = datetime.now().timestamp() * 1000 + (data['expires_in'] * 1000)
        
        # Redirect to frontend dashboard
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}/dashboard?auth=success")
    except Exception as e:
        print(f'OAuth callback error: {str(e)}')
        frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        return redirect(f"{frontend_url}?error=auth_failed")

@wearable_bp.route('/auth/status', methods=['GET'])
def auth_status():
    """
    Check Authentication Status
    ---
    tags:
      - Wearable Integration
    summary: Check if user is authenticated with Google Fit
    responses:
      200:
        description: Authentication status
        schema:
          type: object
          properties:
            authenticated:
              type: boolean
              example: true
    """
    if 'access_token' in session:
        return jsonify({'success': True, 'authenticated': True}), 200
    return jsonify({'success': False, 'authenticated': False}), 200

@wearable_bp.route('/auth/logout', methods=['POST'])
def logout():
    """
    Logout from Google Fit
    ---
    tags:
      - Wearable Integration
    summary: Clear authentication session
    responses:
      200:
        description: Logout successful
        schema:
          type: object
          properties:
            success:
              type: boolean
              example: true
            message:
              type: string
              example: Logged out successfully
    """
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

# ========== Data Source Endpoints ==========

@wearable_bp.route('/datasources', methods=['GET'])
@require_google_auth
def get_datasources():
    """
    Get Available Data Sources
    ---
    tags:
      - Wearable Data
    summary: List all available Google Fit data sources
    security:
      - Bearer: []
    responses:
      200:
        description: List of data sources
      401:
        description: Not authenticated
      500:
        description: Failed to fetch data sources
    """
    try:
        headers = get_authorized_headers()
        response = requests.get(f'{GOOGLE_FIT_API}/dataSources', headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Log available data sources
            print('Available data sources:')
            for source in data.get('dataSource', []):
                print(f"- {source['dataType']['name']}")
            return jsonify({'success': True, 'data': data}), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to fetch data sources'}), 500
    except Exception as e:
        print(f'Data sources error: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500

# ========== Health Data Endpoints ==========

@wearable_bp.route('/heartrate', methods=['GET'])
@require_google_auth
def get_heartrate():
    """
    Get Heart Rate Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve heart rate data from last 24 hours
    security:
      - Bearer: []
    responses:
      200:
        description: Heart rate data
        schema:
          type: object
          properties:
            success:
              type: boolean
            data:
              type: array
              items:
                type: object
                properties:
                  timestamp:
                    type: integer
                  average:
                    type: number
                  min:
                    type: number
                  max:
                    type: number
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        two_days_ago = now - (48 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        # Try primary data type
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.heart_rate.bpm'}],
            'bucketByTime': {'durationMillis': 3600000},  # 1 hour buckets
            'startTimeMillis': two_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        # Try fallback if primary fails
        if response.status_code != 200:
            print('Heart rate data type com.google.heart_rate.bpm failed, trying alternative...')
            payload['aggregateBy'] = [{'dataTypeName': 'com.google.heart_rate.summary'}]
            response = requests.post(
                f'{GOOGLE_FIT_API}/dataset:aggregate',
                json=payload,
                headers=headers
            )
        
        if response.status_code == 200:
            data = response.json()
            one_day_ago = now - (24 * 60 * 60 * 1000)
            
            heart_rate_data = []
            for bucket in data.get('bucket', []):
                if int(bucket['startTimeMillis']) >= one_day_ago:
                    points = bucket.get('dataset', [{}])[0].get('point', [])
                    if points:
                        try:
                            values = [p['value'][0]['fpVal'] for p in points]
                            heart_rate_data.append({
                                'timestamp': int(bucket['startTimeMillis']),
                                'average': sum(values) / len(values),
                                'min': min(values),
                                'max': max(values)
                            })
                        except Exception as e:
                            print(f'Error processing heart rate bucket: {str(e)}')
            
            print(f'Returning {len(heart_rate_data)} heart rate data points')
            return jsonify({'success': True, 'data': heart_rate_data, 'count': len(heart_rate_data)}), 200
        
        return jsonify({'success': False, 'data': [], 'error': response.text}), 200
    except Exception as e:
        print(f'Heart rate error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/steps', methods=['GET'])
@require_google_auth
def get_steps():
    """
    Get Steps Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve daily step count for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Steps data
        schema:
          type: object
          properties:
            success:
              type: boolean
            data:
              type: array
              items:
                type: object
                properties:
                  date:
                    type: string
                  steps:
                    type: integer
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        nine_days_ago = now - (9 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{
                'dataTypeName': 'com.google.step_count.delta',
                'dataSourceId': 'derived:com.google.step_count.delta:com.google.android.gms:estimated_steps'
            }],
            'bucketByTime': {'durationMillis': 86400000},  # 1 day buckets
            'startTimeMillis': nine_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
            
            steps_data = []
            for bucket in data.get('bucket', []):
                timestamp = int(bucket['startTimeMillis'])
                if timestamp >= seven_days_ago:
                    points = bucket.get('dataset', [{}])[0].get('point', [])
                    total_steps = sum(p['value'][0].get('intVal', 0) for p in points)
                    
                    date_str = datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d')
                    steps_data.append({
                        'date': date_str,
                        'steps': total_steps
                    })
            
            steps_data.sort(key=lambda x: x['date'])
            return jsonify({'success': True, 'data': steps_data, 'count': len(steps_data)}), 200
        
        return jsonify({'success': False, 'error': 'Failed to fetch steps data'}), 500
    except Exception as e:
        print(f'Steps error: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500

@wearable_bp.route('/activity', methods=['GET'])
@require_google_auth
def get_activity():
    """
    Get Activity Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve activity segments from last 24 hours
    security:
      - Bearer: []
    responses:
      200:
        description: Activity data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        two_days_ago = now - (48 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.activity.segment'}],
            'startTimeMillis': two_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            activity_types = {
                7: 'Walking',
                8: 'Running',
                1: 'Biking',
                72: 'Sleeping',
                9: 'Aerobics'
            }
            
            one_day_ago = now - (24 * 60 * 60 * 1000)
            activities = []
            
            for bucket in data.get('bucket', []):
                for point in bucket.get('dataset', [{}])[0].get('point', []):
                    start_time = int(point['startTimeNanos']) / 1000000
                    if start_time >= one_day_ago:
                        activity_code = point['value'][0]['intVal']
                        end_time = int(point['endTimeNanos']) / 1000000
                        duration = (int(point['endTimeNanos']) - int(point['startTimeNanos'])) / 1000000000
                        
                        activities.append({
                            'type': activity_types.get(activity_code, f'Activity {activity_code}'),
                            'startTime': start_time,
                            'endTime': end_time,
                            'duration': duration
                        })
            
            return jsonify({'success': True, 'data': activities, 'count': len(activities)}), 200
        
        return jsonify({'success': False, 'error': 'Failed to fetch activity data'}), 500
    except Exception as e:
        print(f'Activity error: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500

@wearable_bp.route('/sleep', methods=['GET'])
@require_google_auth
def get_sleep():
    """
    Get Sleep Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve daily sleep hours for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Sleep data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        nine_days_ago = now - (9 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.sleep.segment'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': nine_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
            
            sleep_data = []
            for bucket in data.get('bucket', []):
                timestamp = int(bucket['startTimeMillis'])
                if timestamp >= seven_days_ago:
                    points = bucket.get('dataset', [{}])[0].get('point', [])
                    total_sleep_ms = 0
                    
                    for point in points:
                        sleep_type = point['value'][0]['intVal']
                        # Sleep types: 1=Awake, 2=Sleep, 3=Out of bed, 4=Light, 5=Deep, 6=REM
                        if sleep_type in [2, 4, 5, 6]:
                            total_sleep_ms += (int(point['endTimeNanos']) - int(point['startTimeNanos'])) / 1000000
                    
                    date_str = datetime.fromtimestamp(timestamp / 1000).strftime('%Y-%m-%d')
                    sleep_data.append({
                        'date': date_str,
                        'sleepHours': total_sleep_ms / (1000 * 60 * 60)
                    })
            
            sleep_data.sort(key=lambda x: x['date'])
            return jsonify({'success': True, 'data': sleep_data, 'count': len(sleep_data)}), 200
        
        return jsonify({'success': False, 'error': 'Failed to fetch sleep data'}), 500
    except Exception as e:
        print(f'Sleep error: {str(e)}')
        return jsonify({'success': False, 'error': str(e)}), 500

@wearable_bp.route('/calories', methods=['GET'])
@require_google_auth
def get_calories():
    """
    Get Calories Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve daily calories burned for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Calories data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.calories.expended'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': seven_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            calories_data = []
            for bucket in data.get('bucket', []):
                points = bucket.get('dataset', [{}])[0].get('point', [])
                total_calories = sum(p['value'][0].get('fpVal', 0) for p in points)
                
                date_str = datetime.fromtimestamp(int(bucket['startTimeMillis']) / 1000).strftime('%Y-%m-%d')
                calories_data.append({
                    'date': date_str,
                    'calories': round(total_calories)
                })
            
            return jsonify({'success': True, 'data': calories_data, 'count': len(calories_data)}), 200
        
        return jsonify({'success': False, 'data': []}), 200
    except Exception as e:
        print(f'Calories error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/weight', methods=['GET'])
@require_google_auth
def get_weight():
    """
    Get Weight Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve daily weight and BMI for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Weight data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.weight'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': seven_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            weight_data = []
            for bucket in data.get('bucket', []):
                points = bucket.get('dataset', [{}])[0].get('point', [])
                if points:
                    last_point = points[-1]
                    weight = last_point['value'][0]['fpVal']
                    bmi = last_point['value'][1]['fpVal'] if len(last_point['value']) > 1 else None
                    
                    date_str = datetime.fromtimestamp(int(bucket['startTimeMillis']) / 1000).strftime('%Y-%m-%d')
                    weight_data.append({
                        'date': date_str,
                        'weight': f"{weight:.1f}",
                        'bmi': f"{bmi:.1f}" if bmi else None
                    })
            
            return jsonify({'success': True, 'data': weight_data, 'count': len(weight_data)}), 200
        
        return jsonify({'success': False, 'data': []}), 200
    except Exception as e:
        print(f'Weight error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/bloodpressure', methods=['GET'])
@require_google_auth
def get_bloodpressure():
    """
    Get Blood Pressure Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve blood pressure readings for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Blood pressure data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.blood_pressure'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': seven_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            bp_data = []
            for bucket in data.get('bucket', []):
                points = bucket.get('dataset', [{}])[0].get('point', [])
                if points:
                    last_point = points[-1]
                    timestamp = int(bucket['startTimeMillis'])
                    
                    bp_data.append({
                        'timestamp': timestamp,
                        'date': datetime.fromtimestamp(timestamp / 1000).strftime('%m/%d/%Y'),
                        'systolic': last_point['value'][0]['fpVal'],
                        'diastolic': last_point['value'][1]['fpVal']
                    })
            
            return jsonify({'success': True, 'data': bp_data, 'count': len(bp_data)}), 200
        
        return jsonify({'success': False, 'data': []}), 200
    except Exception as e:
        print(f'Blood pressure error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/oxygen', methods=['GET'])
@require_google_auth
def get_oxygen():
    """
    Get Oxygen Saturation Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve oxygen saturation (SpO2) for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Oxygen saturation data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.oxygen_saturation'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': seven_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            oxygen_data = []
            for bucket in data.get('bucket', []):
                points = bucket.get('dataset', [{}])[0].get('point', [])
                if points:
                    avg_oxygen = sum(p['value'][0]['fpVal'] for p in points) / len(points)
                    date_str = datetime.fromtimestamp(int(bucket['startTimeMillis']) / 1000).strftime('%Y-%m-%d')
                    
                    oxygen_data.append({
                        'date': date_str,
                        'oxygen': f"{avg_oxygen:.1f}"
                    })
            
            return jsonify({'success': True, 'data': oxygen_data, 'count': len(oxygen_data)}), 200
        
        return jsonify({'success': False, 'data': []}), 200
    except Exception as e:
        print(f'Oxygen error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/distance', methods=['GET'])
@require_google_auth
def get_distance():
    """
    Get Distance Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve daily distance traveled for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Distance data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.distance.delta'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': seven_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            distance_data = []
            for bucket in data.get('bucket', []):
                points = bucket.get('dataset', [{}])[0].get('point', [])
                total_distance = sum(p['value'][0].get('fpVal', 0) for p in points)
                
                date_str = datetime.fromtimestamp(int(bucket['startTimeMillis']) / 1000).strftime('%Y-%m-%d')
                distance_data.append({
                    'date': date_str,
                    'distance': round(total_distance)
                })
            
            return jsonify({'success': True, 'data': distance_data, 'count': len(distance_data)}), 200
        
        return jsonify({'success': False, 'data': []}), 200
    except Exception as e:
        print(f'Distance error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/speed', methods=['GET'])
@require_google_auth
def get_speed():
    """
    Get Speed Data
    ---
    tags:
      - Wearable Data
    summary: Retrieve average speed for last 7 days
    security:
      - Bearer: []
    responses:
      200:
        description: Speed data
      401:
        description: Not authenticated
    """
    try:
        now = int(datetime.now().timestamp() * 1000)
        seven_days_ago = now - (7 * 24 * 60 * 60 * 1000)
        
        headers = get_authorized_headers()
        
        payload = {
            'aggregateBy': [{'dataTypeName': 'com.google.speed'}],
            'bucketByTime': {'durationMillis': 86400000},
            'startTimeMillis': seven_days_ago,
            'endTimeMillis': now
        }
        
        response = requests.post(
            f'{GOOGLE_FIT_API}/dataset:aggregate',
            json=payload,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            
            speed_data = []
            for bucket in data.get('bucket', []):
                points = bucket.get('dataset', [{}])[0].get('point', [])
                if points:
                    avg_speed = sum(p['value'][0]['fpVal'] for p in points) / len(points)
                    date_str = datetime.fromtimestamp(int(bucket['startTimeMillis']) / 1000).strftime('%Y-%m-%d')
                    
                    speed_data.append({
                        'date': date_str,
                        'speed': f"{avg_speed:.2f}"
                    })
            
            return jsonify({'success': True, 'data': speed_data, 'count': len(speed_data)}), 200
        
        return jsonify({'success': False, 'data': []}), 200
    except Exception as e:
        print(f'Speed error: {str(e)}')
        return jsonify({'success': False, 'data': [], 'error': str(e)}), 500

@wearable_bp.route('/config/test', methods=['GET'])
def test_config():
    """
    Test Configuration
    ---
    tags:
      - Wearable Integration
    summary: Test if environment variables are loaded correctly
    responses:
      200:
        description: Configuration status
    """
    return jsonify({
        'success': True,
        'config': {
            'google_client_id_set': bool(os.getenv('GOOGLE_CLIENT_ID')),
            'google_client_secret_set': bool(os.getenv('GOOGLE_CLIENT_SECRET')),
            'redirect_uri': os.getenv('REDIRECT_URI'),
            'frontend_url': os.getenv('FRONTEND_URL'),
            'session_secret_set': bool(os.getenv('SESSION_SECRET'))
        },
        'message': 'All credentials configured!' if os.getenv('GOOGLE_CLIENT_ID') else 'Missing Google credentials'
    }), 200
