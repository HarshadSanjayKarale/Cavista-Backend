"""
Risk Assessment Routes
ML-powered health risk predictions
"""
from flask import Blueprint, jsonify, request
from app.services.risk_prediction_service import risk_service

risk_bp = Blueprint('risk_assessment', __name__)

@risk_bp.route('/predict/<user_id>', methods=['GET'])
def predict_user_risk(user_id):
    """
    Predict Health Risk for User
    ---
    tags:
      - Risk Assessment
    summary: Get comprehensive health risk prediction for a user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Risk prediction successful
        schema:
          type: object
          properties:
            success:
              type: boolean
            data:
              type: object
              properties:
                risk_assessment:
                  type: object
                health_metrics:
                  type: object
                derived_scores:
                  type: object
                risk_factors:
                  type: object
                recommendations:
                  type: array
      404:
        description: No data found for user
      500:
        description: Prediction failed
    """
    try:
        result = risk_service.predict_risk(user_id)
        
        return jsonify({
            'success': True,
            'message': 'Risk prediction completed successfully',
            'data': result
        }), 200
        
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'No wearable data found for this user. Please sync wearable data first.'
        }), 404
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'Risk prediction failed'
        }), 500

@risk_bp.route('/batch-predict', methods=['POST'])
def batch_predict_risk():
    """
    Batch Risk Prediction
    ---
    tags:
      - Risk Assessment
    summary: Predict risk for multiple users
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          properties:
            user_ids:
              type: array
              items:
                type: string
              description: List of user IDs
    responses:
      200:
        description: Batch prediction completed
    """
    try:
        data = request.get_json()
        user_ids = data.get('user_ids', [])
        
        if not user_ids:
            return jsonify({
                'success': False,
                'error': 'user_ids array is required'
            }), 400
        
        results = []
        errors = []
        
        for user_id in user_ids:
            try:
                prediction = risk_service.predict_risk(user_id)
                results.append(prediction)
            except Exception as e:
                errors.append({
                    'user_id': user_id,
                    'error': str(e)
                })
        
        return jsonify({
            'success': True,
            'message': f'Processed {len(results)} users successfully',
            'total_requested': len(user_ids),
            'successful': len(results),
            'failed': len(errors),
            'data': results,
            'errors': errors if errors else None
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@risk_bp.route('/model-info', methods=['GET'])
def get_model_info():
    """
    Get Model Information
    ---
    tags:
      - Risk Assessment
    summary: Get information about the risk prediction model
    responses:
      200:
        description: Model information retrieved
    """
    try:
        return jsonify({
            'success': True,
            'model_info': {
                'version': risk_service.version,
                'features': risk_service.features,
                'feature_count': len(risk_service.features),
                'risk_classes': ['Low (0-25%)', 'Moderate (25-50%)', 'High (50-75%)', 'Critical (75-100%)']
            }
        }), 200
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@risk_bp.route('/health-summary/<user_id>', methods=['GET'])
def get_health_summary(user_id):
    """
    Get Health Summary
    ---
    tags:
      - Risk Assessment
    summary: Get simplified health summary for a user
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Health summary retrieved
    """
    try:
        result = risk_service.predict_risk(user_id)
        
        # Simplified summary
        summary = {
            'user_id': user_id,
            'risk_level': result['risk_assessment']['risk_class'],
            'risk_percentage': result['risk_assessment']['risk_percentage'],
            'health_score': result['derived_scores']['health_score'],
            'key_metrics': {
                'steps': result['health_metrics']['steps'],
                'sleep_hrs': result['health_metrics']['sleep_hrs'],
                'heart_rate': result['health_metrics']['heart_rate'],
                'bmi': result['health_metrics']['bmi']
            },
            'top_recommendations': result['recommendations'][:3]
        }
        
        return jsonify({
            'success': True,
            'data': summary
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500