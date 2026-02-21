from datetime import datetime
from bson import ObjectId
from typing import Optional, Dict

class NotificationModel:
    def __init__(self, db):
        self.collection = db['notifications']
    
    def create_notification(self, user_id, message, title=None,
                            notification_type='general', data=None):
        """Create a new notification.

        Args:
            user_id: Target user ObjectId string.
            message: Notification body text.
            title: Optional short heading.
            notification_type: Category tag (general, vitals_critical, etc.).
            data: Optional extra payload dict.
        """
        notification = {
            "user_id": user_id,
            "title": title or "",
            "message": message,
            "type": notification_type,
            "data": data or {},
            "is_read": False,
            "created_at": datetime.utcnow()
        }
        result = self.collection.insert_one(notification)
        notification['_id'] = str(result.inserted_id)
        return notification
    
    def get_user_notifications(self, user_id, skip=0, limit=20):
        """Get all notifications for a user"""
        notifications = list(self.collection.find(
            {"user_id": user_id}
        ).sort("created_at", -1).skip(skip).limit(limit))
        
        for notif in notifications:
            notif['_id'] = str(notif['_id'])
        
        return notifications
    
    def get_unread_count(self, user_id):
        """Get count of unread notifications"""
        return self.collection.count_documents({
            "user_id": user_id,
            "is_read": False
        })
    
    def mark_as_read(self, notification_id, user_id):
        """Mark a notification as read"""
        result = self.collection.update_one(
            {"_id": ObjectId(notification_id), "user_id": user_id},
            {"$set": {"is_read": True}}
        )
        return result.modified_count > 0
    
    def mark_all_as_read(self, user_id):
        """Mark all notifications as read for a user"""
        result = self.collection.update_many(
            {"user_id": user_id, "is_read": False},
            {"$set": {"is_read": True}}
        )
        return result.modified_count
    
    def delete_notification(self, notification_id, user_id):
        """Delete a notification"""
        result = self.collection.delete_one(
            {"_id": ObjectId(notification_id), "user_id": user_id}
        )
        return result.deleted_count > 0