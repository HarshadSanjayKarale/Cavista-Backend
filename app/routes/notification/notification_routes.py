from flask import Blueprint, request, g
from app.models.notification.notification_model import NotificationModel
from app.services.notification_manager import NotificationManager
from app.utils.response_utils import success_response, error_response, paginated_response, validation_error_response

notification_bp = Blueprint('notification', __name__)


def get_notification_model():
    from flask import current_app
    return NotificationModel(current_app.db)


def get_notification_manager():
    from flask import current_app
    return NotificationManager(current_app.db)


# =====================================================================
#  EXISTING CRUD ENDPOINTS (unchanged behaviour)
# =====================================================================

@notification_bp.route('/notifications', methods=['POST'])
# @token_required  # Comment out for now
def create_notification():
    """Create a new notification for a specific user"""
    try:
        data = request.get_json()
        
        # Validation
        if not data:
            return error_response("Request body is required", 400)
        
        user_id = data.get('user_id')
        message = data.get('message')
        
        errors = {}
        if not user_id:
            errors['user_id'] = "User ID is required"
        if not message:
            errors['message'] = "Message is required"
        
        if errors:
            return validation_error_response(errors)
        
        notification_model = get_notification_model()
        notification = notification_model.create_notification(user_id, message)
        
        return success_response(
            "Notification created successfully",
            notification,
            201
        )
    except Exception as e:
        return error_response(f"Failed to create notification: {str(e)}", 500)

@notification_bp.route('/notifications', methods=['GET'])
# @token_required  # Comment out for now
def get_notifications():
    """Get all notifications for a user"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return error_response("user_id query parameter is required", 400)
        
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        skip = (page - 1) * per_page
        
        notification_model = get_notification_model()
        notifications = notification_model.get_user_notifications(
            user_id, 
            skip=skip, 
            limit=per_page
        )
        
        total = notification_model.collection.count_documents({
            "user_id": user_id
        })
        
        return paginated_response(
            "Notifications retrieved successfully",
            notifications,
            page,
            per_page,
            total
        )
    except Exception as e:
        return error_response(f"Failed to retrieve notifications: {str(e)}", 500)

@notification_bp.route('/notifications/unread-count', methods=['GET'])
# @token_required
def get_unread_count():
    """Get count of unread notifications"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return error_response("user_id query parameter is required", 400)
        
        notification_model = get_notification_model()
        count = notification_model.get_unread_count(user_id)
        
        return success_response(
            "Unread count retrieved successfully",
            {"unread_count": count}
        )
    except Exception as e:
        return error_response(f"Failed to get unread count: {str(e)}", 500)

@notification_bp.route('/notifications/<notification_id>/read', methods=['PATCH'])
# @token_required
def mark_notification_read(notification_id):
    """Mark a specific notification as read"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return error_response("user_id query parameter is required", 400)
        
        notification_model = get_notification_model()
        success = notification_model.mark_as_read(notification_id, user_id)
        
        if success:
            return success_response("Notification marked as read")
        else:
            return error_response("Notification not found", 404)
    except Exception as e:
        return error_response(f"Failed to mark notification as read: {str(e)}", 500)

@notification_bp.route('/notifications/mark-all-read', methods=['PATCH'])
# @token_required
def mark_all_read():
    """Mark all notifications as read"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return error_response("user_id query parameter is required", 400)
        
        notification_model = get_notification_model()
        count = notification_model.mark_all_as_read(user_id)
        
        return success_response(
            "All notifications marked as read",
            {"updated_count": count}
        )
    except Exception as e:
        return error_response(f"Failed to mark all as read: {str(e)}", 500)

@notification_bp.route('/notifications/<notification_id>', methods=['DELETE'])
# @token_required
def delete_notification(notification_id):
    """Delete a notification"""
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return error_response("user_id query parameter is required", 400)
        
        notification_model = get_notification_model()
        success = notification_model.delete_notification(notification_id, user_id)
        
        if success:
            return success_response("Notification deleted successfully")
        else:
            return error_response("Notification not found", 404)
    except Exception as e:
        return error_response(f"Failed to delete notification: {str(e)}", 500)


# =====================================================================
#  NEW — Alert endpoints (FCM + SMS)
# =====================================================================

@notification_bp.route('/alert/doctors', methods=['POST'])
def alert_connected_doctors():
    """
    Notify all doctors connected to a patient.
    Optionally also SMS the patient's emergency contacts.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
            - title
            - message
          properties:
            patient_id:
              type: string
              description: Patient's ObjectId
            title:
              type: string
            message:
              type: string
            notification_type:
              type: string
              default: patient_alert
            send_push:
              type: boolean
              default: true
            send_sms_to_relatives:
              type: boolean
              default: false
            sms_alert_type:
              type: string
              default: health_alert
            sms_details:
              type: string
              default: ""
    responses:
      200:
        description: Notifications dispatched
      400:
        description: Validation error
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        patient_id = data.get('patient_id')
        title = data.get('title')
        message = data.get('message')

        errors = {}
        if not patient_id:
            errors['patient_id'] = "Patient ID is required"
        if not title:
            errors['title'] = "Title is required"
        if not message:
            errors['message'] = "Message is required"
        if errors:
            return validation_error_response(errors)

        mgr = get_notification_manager()
        result = mgr.notify_connected_doctors(
            patient_id=patient_id,
            title=title,
            message=message,
            notification_type=data.get('notification_type', 'patient_alert'),
            send_push=data.get('send_push', True),
            send_sms_to_relatives=data.get('send_sms_to_relatives', False),
            sms_alert_type=data.get('sms_alert_type', 'health_alert'),
            sms_details=data.get('sms_details', ''),
        )

        return success_response("Doctors notified successfully", result)

    except Exception as e:
        return error_response(f"Failed to alert doctors: {str(e)}", 500)


@notification_bp.route('/alert/emergency', methods=['POST'])
def alert_emergency():
    """
    🚨 Send an EMERGENCY alert — triggers alarm-style notification on mobile.
    Notifies all connected doctors (FCM push with type='emergency') + SMS to relatives.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
            - alert_type
          properties:
            patient_id:
              type: string
              description: Patient's ObjectId
            alert_type:
              type: string
              description: e.g. 'sos', 'fall_detected', 'vitals_critical', 'panic_button'
            title:
              type: string
              description: Custom notification title (optional, auto-generated if empty)
            message:
              type: string
              description: Custom notification body (optional, auto-generated if empty)
            details:
              type: string
              description: Extra info included in SMS body
              default: ""
    responses:
      200:
        description: Emergency alert dispatched to doctors + SMS to relatives
      400:
        description: Validation error
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        patient_id = data.get('patient_id')
        alert_type = data.get('alert_type')

        errors = {}
        if not patient_id:
            errors['patient_id'] = "Patient ID is required"
        if not alert_type:
            errors['alert_type'] = "Alert type is required (e.g. 'sos', 'fall_detected')"
        if errors:
            return validation_error_response(errors)

        mgr = get_notification_manager()
        result = mgr.send_emergency_alert(
            patient_id=patient_id,
            alert_type=alert_type,
            title=data.get('title', ''),
            message=data.get('message', ''),
            details=data.get('details', ''),
        )

        return success_response("🚨 Emergency alert dispatched", result)

    except Exception as e:
        return error_response(f"Emergency alert failed: {str(e)}", 500)


@notification_bp.route('/alert/vitals-critical', methods=['POST'])
def alert_vitals_critical():
    """
    Quick endpoint: patient vitals are critical -> EMERGENCY alert to doctors + SMS relatives.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
            - vitals_summary
          properties:
            patient_id:
              type: string
            vitals_summary:
              type: string
    responses:
      200:
        description: Emergency alert dispatched
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        patient_id = data.get('patient_id')
        vitals_summary = data.get('vitals_summary')

        if not patient_id or not vitals_summary:
            return error_response("patient_id and vitals_summary are required", 400)

        mgr = get_notification_manager()
        result = mgr.on_vitals_critical(patient_id, vitals_summary)
        return success_response("Vitals-critical alert sent", result)

    except Exception as e:
        return error_response(f"Vitals alert failed: {str(e)}", 500)


@notification_bp.route('/alert/fall-detected', methods=['POST'])
def alert_fall_detected():
    """
    Quick endpoint: fall detected -> notify doctors + SMS relatives.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
          properties:
            patient_id:
              type: string
            location:
              type: string
    responses:
      200:
        description: Alert dispatched
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        patient_id = data.get('patient_id')
        if not patient_id:
            return error_response("patient_id is required", 400)

        mgr = get_notification_manager()
        result = mgr.on_fall_detected(patient_id, data.get('location', ''))
        return success_response("Fall-detected alert sent", result)

    except Exception as e:
        return error_response(f"Fall alert failed: {str(e)}", 500)


@notification_bp.route('/alert/medication-missed', methods=['POST'])
def alert_medication_missed():
    """
    Quick endpoint: patient missed medication -> notify doctors.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
            - medication_name
          properties:
            patient_id:
              type: string
            medication_name:
              type: string
    responses:
      200:
        description: Alert dispatched
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        patient_id = data.get('patient_id')
        medication_name = data.get('medication_name')

        if not patient_id or not medication_name:
            return error_response("patient_id and medication_name are required", 400)

        mgr = get_notification_manager()
        result = mgr.on_medication_missed(patient_id, medication_name)
        return success_response("Medication-missed alert sent", result)

    except Exception as e:
        return error_response(f"Medication alert failed: {str(e)}", 500)


@notification_bp.route('/send-push', methods=['POST'])
def send_push_notification():
    """
    Send a push notification (FCM) to a single user by user_id.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - user_id
            - title
            - message
          properties:
            user_id:
              type: string
            title:
              type: string
            message:
              type: string
            notification_type:
              type: string
              default: general
    responses:
      200:
        description: Notification sent
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        user_id = data.get('user_id')
        title = data.get('title')
        message = data.get('message')

        errors = {}
        if not user_id:
            errors['user_id'] = "User ID is required"
        if not title:
            errors['title'] = "Title is required"
        if not message:
            errors['message'] = "Message is required"
        if errors:
            return validation_error_response(errors)

        mgr = get_notification_manager()
        notif = mgr.notify_user(
            user_id=user_id,
            title=title,
            message=message,
            notification_type=data.get('notification_type', 'general'),
            send_push=True,
        )

        return success_response("Notification sent", notif, 201)

    except Exception as e:
        return error_response(f"Push notification failed: {str(e)}", 500)


@notification_bp.route('/send-sms', methods=['POST'])
def send_sms_to_contacts():
    """
    Manually trigger SMS to a patient's emergency contacts.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - patient_id
            - alert_type
          properties:
            patient_id:
              type: string
            alert_type:
              type: string
            details:
              type: string
              default: ""
    responses:
      200:
        description: SMS result
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        patient_id = data.get('patient_id')
        alert_type = data.get('alert_type')

        if not patient_id or not alert_type:
            return error_response("patient_id and alert_type are required", 400)

        mgr = get_notification_manager()
        result = mgr._send_sms_to_contacts(
            patient_id=patient_id,
            alert_type=alert_type,
            details=data.get('details', ''),
        )

        return success_response("SMS alert dispatched", result)

    except Exception as e:
        return error_response(f"SMS alert failed: {str(e)}", 500)


@notification_bp.route('/register-fcm-token', methods=['POST'])
def register_fcm_token():
    """
    Register / update a user's FCM device token.
    Call this from the mobile app after obtaining the FCM token.
    ---
    tags:
      - Notifications
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - user_id
            - fcm_token
          properties:
            user_id:
              type: string
            fcm_token:
              type: string
    responses:
      200:
        description: Token registered
    """
    try:
        data = request.get_json()
        if not data:
            return error_response("Request body is required", 400)

        user_id = data.get('user_id')
        fcm_token = data.get('fcm_token')

        if not user_id or not fcm_token:
            return error_response("user_id and fcm_token are required", 400)

        from flask import current_app
        from bson import ObjectId

        result = current_app.db['users'].update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'fcm_token': fcm_token}},
        )

        if result.matched_count == 0:
            return error_response("User not found", 404)

        return success_response("FCM token registered successfully")

    except Exception as e:
        return error_response(f"Token registration failed: {str(e)}", 500)