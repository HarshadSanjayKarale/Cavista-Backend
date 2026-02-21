"""
Firebase Cloud Messaging Service
================================
Handles sending push notifications via FCM to mobile devices.
Designed as a pluggable module — remove this file and its import
in notification_manager.py to disable FCM entirely.

Author: Cavista Team
Version: 1.0.0
"""

import firebase_admin
from firebase_admin import credentials, messaging
import os
from typing import List, Optional, Dict


class FCMService:
    """
    Firebase Cloud Messaging Service for sending push notifications.
    Singleton — only one instance is ever created.
    """

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FCMService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialize Firebase Admin SDK (only once)."""
        if not FCMService._initialized:
            try:
                firebase_admin.get_app()
                print("✅ Firebase Admin SDK already initialized")
            except ValueError:
                service_account_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH')

                if service_account_path and os.path.exists(service_account_path):
                    cred = credentials.Certificate(service_account_path)
                    firebase_admin.initialize_app(cred)
                    print(f"✅ Firebase Admin SDK initialized from file: {service_account_path}")
                else:
                    try:
                        cred = credentials.ApplicationDefault()
                        firebase_admin.initialize_app(cred)
                        print("✅ Firebase Admin SDK initialized with default credentials")
                    except Exception as e:
                        print(f"⚠️  Firebase Admin SDK not initialized: {e}")
                        print("ℹ️  Set FIREBASE_SERVICE_ACCOUNT_PATH env variable to enable FCM.")

            FCMService._initialized = True

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    @property
    def is_available(self) -> bool:
        """Return True when FCM is ready to send."""
        try:
            firebase_admin.get_app()
            return True
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Send to a single device
    # ------------------------------------------------------------------
    def send_notification(
        self,
        fcm_token: str,
        title: str,
        body: str,
        data: Optional[Dict[str, str]] = None,
        notification_type: str = 'general',
    ) -> bool:
        """
        Send a push notification to **one** device.

        Args:
            fcm_token: Device FCM token.
            title: Notification title.
            body: Notification body text.
            data: Optional extra key-value payload.
            notification_type: Category tag (e.g. vitals_alert, appointment).

        Returns:
            True on success, False otherwise.
        """
        try:
            if not self.is_available or not fcm_token:
                return False

            data_payload = {k: str(v) for k, v in (data or {}).items()}
            data_payload['type'] = str(notification_type)
            data_payload['click_action'] = 'FLUTTER_NOTIFICATION_CLICK'

            message = messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data=data_payload,
                token=fcm_token,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        channel_id='high_importance_channel',
                        priority='high',
                        sound='default',
                    ),
                ),
                apns=messaging.APNSConfig(
                    headers={'apns-priority': '10'},
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            alert=messaging.ApsAlert(title=title, body=body),
                            badge=1,
                            sound='default',
                        ),
                    ),
                ),
            )

            response = messaging.send(message)
            print(f"✅ FCM sent → {response}")
            return True

        except Exception as e:
            print(f"❌ FCM send error: {e}")
            return False

    # ------------------------------------------------------------------
    # Send to many devices at once
    # ------------------------------------------------------------------
    def send_multicast_notification(
        self,
        fcm_tokens: List[str],
        title: str,
        body: str,
        data: Optional[Dict[str, str]] = None,
        notification_type: str = 'general',
    ) -> Dict[str, int]:
        """
        Send a push notification to **multiple** devices.

        Returns:
            {'success_count': int, 'failure_count': int}
        """
        try:
            if not self.is_available or not fcm_tokens:
                return {'success_count': 0, 'failure_count': len(fcm_tokens or [])}

            valid_tokens = [t for t in fcm_tokens if t]
            if not valid_tokens:
                return {'success_count': 0, 'failure_count': 0}

            data_payload = {k: str(v) for k, v in (data or {}).items()}
            data_payload['type'] = str(notification_type)
            data_payload['click_action'] = 'FLUTTER_NOTIFICATION_CLICK'

            message = messaging.MulticastMessage(
                notification=messaging.Notification(title=title, body=body),
                data=data_payload,
                tokens=valid_tokens,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        channel_id='high_importance_channel',
                        priority='high',
                        sound='default',
                    ),
                ),
                apns=messaging.APNSConfig(
                    headers={'apns-priority': '10'},
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            alert=messaging.ApsAlert(title=title, body=body),
                            badge=1,
                            sound='default',
                        ),
                    ),
                ),
            )

            response = messaging.send_multicast(message)
            print(f"✅ FCM multicast → success={response.success_count}, fail={response.failure_count}")
            return {
                'success_count': response.success_count,
                'failure_count': response.failure_count,
            }

        except Exception as e:
            print(f"❌ FCM multicast error: {e}")
            return {'success_count': 0, 'failure_count': len(fcm_tokens or [])}

    # ------------------------------------------------------------------
    # Send to a topic (broadcast)
    # ------------------------------------------------------------------
    def send_topic_notification(
        self,
        topic: str,
        title: str,
        body: str,
        data: Optional[Dict[str, str]] = None,
        notification_type: str = 'general',
    ) -> bool:
        """Send a push notification to all devices subscribed to *topic*."""
        try:
            if not self.is_available:
                return False

            data_payload = {k: str(v) for k, v in (data or {}).items()}
            data_payload['type'] = str(notification_type)
            data_payload['click_action'] = 'FLUTTER_NOTIFICATION_CLICK'

            message = messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                data=data_payload,
                topic=topic,
                android=messaging.AndroidConfig(
                    priority='high',
                    notification=messaging.AndroidNotification(
                        channel_id='high_importance_channel',
                        priority='high',
                        sound='default',
                    ),
                ),
                apns=messaging.APNSConfig(
                    headers={'apns-priority': '10'},
                    payload=messaging.APNSPayload(
                        aps=messaging.Aps(
                            alert=messaging.ApsAlert(title=title, body=body),
                            badge=1,
                            sound='default',
                        ),
                    ),
                ),
            )

            response = messaging.send(message)
            print(f"✅ FCM topic '{topic}' → {response}")
            return True

        except Exception as e:
            print(f"❌ FCM topic error: {e}")
            return False


# Singleton instance – import this wherever needed
fcm_service = FCMService()
