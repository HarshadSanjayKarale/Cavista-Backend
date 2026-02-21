"""
Clinical Narrative Routes
AI-powered clinical narrative generation from risk assessments
"""
from flask import Blueprint, jsonify, request
from app.services.risk_prediction_service import risk_service
from app.services.clinical_narrative_service import clinical_narrative_service

clinical_bp = Blueprint('clinical_narrative', __name__)

@clinical_bp.route('/generate/<user_id>', methods=['GET'])
def generate_clinical_narrative(user_id):
    """
    Generate Clinical Narrative
    ---
    tags:
      - Clinical Narrative
    summary: Generate AI-powered clinical narrative from risk assessment
    description: Uses multi-agent LLM system to interpret risk data and create comprehensive clinical reports
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: User ID
    responses:
      200:
        description: Clinical narrative generated successfully
        schema:
          type: object
          properties:
            success:
              type: boolean
              example: true
            data:
              type: object
              properties:
                user_id:
                  type: string
                clinical_narrative:
                  type: string
                  description: AI-generated clinical narrative
                structured_assessment:
                  type: object
                  description: Original risk assessment data
                report_metadata:
                  type: object
      404:
        description: No wearable data found
      500:
        description: Generation failed
    """
    try:
        # Step 1: Get risk assessment from ML model
        risk_assessment = risk_service.predict_risk(user_id)
        
        # Step 2: Generate clinical narrative using LLM agent
        clinical_report = clinical_narrative_service.generate_comprehensive_report(
            user_id=user_id,
            risk_assessment_data=risk_assessment
        )
        
        return jsonify({
            'success': True,
            'message': 'Clinical narrative generated successfully',
            'data': clinical_report
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
            'message': 'Failed to generate clinical narrative'
        }), 500

@clinical_bp.route('/narrative-only/<user_id>', methods=['GET'])
def get_narrative_only(user_id):
    """
    Get Narrative Only
    ---
    tags:
      - Clinical Narrative
    summary: Get only the AI-generated clinical narrative text
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Narrative retrieved
        schema:
          type: object
          properties:
            success:
              type: boolean
            user_id:
              type: string
            narrative:
              type: string
    """
    try:
        # Get risk assessment
        risk_assessment = risk_service.predict_risk(user_id)
        
        # Generate narrative
        narrative = clinical_narrative_service.risk_interpreter.generate_narrative(
            user_id=user_id,
            risk_assessment_data=risk_assessment
        )
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'narrative': narrative
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@clinical_bp.route('/batch-generate', methods=['POST'])
def batch_generate_narratives():
    """
    Batch Generate Narratives
    ---
    tags:
      - Clinical Narrative
    summary: Generate clinical narratives for multiple users
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
              example: ["USR_001", "USR_002", "USR_003"]
    responses:
      200:
        description: Batch generation completed
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
                # Get risk assessment
                risk_assessment = risk_service.predict_risk(user_id)
                
                # Generate clinical report
                report = clinical_narrative_service.generate_comprehensive_report(
                    user_id=user_id,
                    risk_assessment_data=risk_assessment
                )
                
                results.append(report)
                
            except Exception as e:
                errors.append({
                    'user_id': user_id,
                    'error': str(e)
                })
        
        return jsonify({
            'success': True,
            'message': f'Generated {len(results)} clinical narratives',
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

@clinical_bp.route('/compare-narrative/<user_id>', methods=['GET'])
def compare_with_narrative(user_id):
    """
    Compare with Narrative
    ---
    tags:
      - Clinical Narrative
    summary: Get both structured data and clinical narrative side-by-side
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: Comparison retrieved
    """
    try:
        # Get risk assessment
        risk_assessment = risk_service.predict_risk(user_id)
        
        # Generate narrative
        narrative = clinical_narrative_service.risk_interpreter.generate_narrative(
            user_id=user_id,
            risk_assessment_data=risk_assessment
        )
        
        return jsonify({
            'success': True,
            'user_id': user_id,
            'comparison': {
                'structured_data': risk_assessment,
                'clinical_narrative': narrative
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500