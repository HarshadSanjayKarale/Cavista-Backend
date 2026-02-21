from flask import Blueprint, request, g
from app.models.notification.notification_model import NotificationModel
from app.utils.response_utils import success_response, error_response, paginated_response, validation_error_response
# Remove or update this import based on your actual auth implementation
# from app.middleware.auth_middleware import token_required

notification_bp = Blueprint('notification', __name__)

def get_notification_model():
    from flask import current_app
    return NotificationModel(current_app.db)

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