"""
Diet Recommendation Routes
API endpoints for personalized diet recommendations
"""
from flask import Blueprint, request, jsonify
from app.services.diet_recommendation_service import diet_recommendation_service
from app.services.risk_prediction_service import risk_service
from app.extensions import mongo
from bson import ObjectId
from datetime import datetime

diet_bp = Blueprint('diet', __name__)

@diet_bp.route('/recommend/<user_id>', methods=['POST'])
def get_diet_recommendation(user_id):
    """
    Generate personalized diet plan based on latest risk assessment
    ---
    tags:
      - Diet Recommendations
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: Patient ID
      - name: body
        in: body
        required: false
        schema:
          type: object
          properties:
            assessment_date:
              type: string
              description: Specific date for assessment (YYYY-MM-DD), defaults to today
            auto_assess:
              type: boolean
              description: Auto-generate risk assessment if none exists (default true)
    responses:
      200:
        description: Diet plan generated successfully
      404:
        description: No risk assessment or wearable data found
      500:
        description: Server error
    """
    try:
        data = request.get_json() or {}
        assessment_date = data.get('assessment_date', datetime.now().strftime('%Y-%m-%d'))
        auto_assess = data.get('auto_assess', True)
        
        # Get the latest risk assessment for this user
        risk_assessment = mongo.db.risk_assessments.find_one(
            {'user_id': user_id},
            sort=[('timestamp', -1)]
        )
        
        # If no risk assessment exists and auto_assess is True, generate one
        if not risk_assessment and auto_assess:
            try:
                print(f"📊 No risk assessment found for {user_id}. Generating new assessment...")
                
                # Run risk prediction
                risk_result = risk_service.predict_risk(user_id)
                
                # Store risk assessment in database
                risk_assessment = risk_result.copy()
                risk_assessment['timestamp'] = datetime.utcnow()
                
                mongo.db.risk_assessments.insert_one(risk_assessment)
                print(f"✅ Risk assessment generated and stored for {user_id}")
                
                # Remove MongoDB _id for JSON serialization
                risk_assessment.pop('_id', None)
                
            except ValueError as ve:
                return jsonify({
                    'success': False,
                    'error': f'Cannot generate diet plan: {str(ve)}',
                    'hint': 'Please ensure wearable data exists for this user by syncing from Google Fit or submitting mock data.'
                }), 404
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Failed to generate risk assessment: {str(e)}'
                }), 500
        
        elif not risk_assessment:
            return jsonify({
                'success': False,
                'error': f'No risk assessment found for user {user_id}.',
                'hint': 'Please run risk assessment first at POST /api/risk/predict/{user_id} or enable auto_assess'
            }), 404
        
        # Remove MongoDB _id for JSON serialization
        risk_assessment.pop('_id', None)
        
        # Generate diet plan
        print(f"🍽️  Generating diet plan for {user_id}...")
        diet_plan = diet_recommendation_service.get_personalized_diet_plan(
            user_id=user_id,
            risk_assessment_data=risk_assessment,
            assessment_date=assessment_date
        )
        
        # Store diet plan in database
        diet_plan_copy = diet_plan.copy()
        diet_plan_copy['timestamp'] = datetime.utcnow()
        
        result = mongo.db.diet_plans.insert_one(diet_plan_copy)
        diet_plan['_id'] = str(result.inserted_id)
        diet_plan['timestamp'] = diet_plan_copy['timestamp'].isoformat()
        
        return jsonify({
            'success': True,
            'message': 'Diet plan generated successfully',
            'data': diet_plan
        }), 200
        
    except Exception as e:
        print(f"❌ Error in diet recommendation: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@diet_bp.route('/history/<user_id>', methods=['GET'])
def get_diet_history(user_id):
    """
    Get diet plan history for a user
    ---
    tags:
      - Diet Recommendations
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: Patient ID
      - name: limit
        in: query
        type: integer
        default: 10
        description: Number of records to retrieve
    responses:
      200:
        description: Diet plan history retrieved
    """
    try:
        limit = int(request.args.get('limit', 10))
        
        diet_plans = list(mongo.db.diet_plans.find(
            {'user_id': user_id},
            sort=[('timestamp', -1)],
            limit=limit
        ))
        
        # Convert ObjectId to string and datetime to ISO format
        for plan in diet_plans:
            plan['_id'] = str(plan['_id'])
            if 'timestamp' in plan:
                plan['timestamp'] = plan['timestamp'].isoformat()
        
        return jsonify({
            'success': True,
            'count': len(diet_plans),
            'data': diet_plans
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@diet_bp.route('/latest/<user_id>', methods=['GET'])
def get_latest_diet_plan(user_id):
    """
    Get the latest diet plan for a user
    ---
    tags:
      - Diet Recommendations
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: Patient ID
    responses:
      200:
        description: Latest diet plan retrieved
      404:
        description: No diet plan found
    """
    try:
        diet_plan = mongo.db.diet_plans.find_one(
            {'user_id': user_id},
            sort=[('timestamp', -1)]
        )
        
        if not diet_plan:
            return jsonify({
                'success': False,
                'error': 'No diet plan found for this user',
                'hint': 'Generate a diet plan at POST /api/diet/recommend/{user_id}'
            }), 404
        
        diet_plan['_id'] = str(diet_plan['_id'])
        if 'timestamp' in diet_plan:
            diet_plan['timestamp'] = diet_plan['timestamp'].isoformat()
        
        return jsonify({
            'success': True,
            'data': diet_plan
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500