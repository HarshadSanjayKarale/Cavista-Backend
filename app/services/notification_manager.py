"""
Notification Manager
====================
Unified orchestrator that ties together:
  • In-app notifications  (MongoDB – always on)
  • FCM push notifications (optional – remove fcm_service import to disable)
  • SMS alerts to relatives (optional – remove sms_service import to disable)

Each channel is **pluggable**. To disable a channel:
  1. Delete or comment out its import below.
  2. Set the matching flag in the constructor to False.
  That's it — no other files need to change.

Author: Cavista Team
Version: 1.0.0
"""

from datetime import datetime
from typing import Optional, Dict, List
from bson import ObjectId

# ── Pluggable channel imports ───────────────────────────────────────
# Comment out / remove a line to disable that channel entirely.
from app.services.fcm_service import fcm_service       # Push notifications
from app.services.sms_service import sms_service        # SMS alerts
# ────────────────────────────────────────────────────────────────────


class NotificationManager:
    """
    Central service that every part of the app calls to send notifications.
    It fans out to:
        1. MongoDB (in-app notification record)
        2. FCM push (if fcm_service is imported & available)
        3. SMS to relatives / emergency contacts (if sms_service is imported & available)
    """

    def __init__(self, db):
        """
        Args:
            db: PyMongo database object (``current_app.db`` or ``mongo.db``).
        """
        self.db = db
        self.notifications = db['notifications']
        self.users = db['users']
        self.connections = db['connections']

        # ── Feature flags (override via env or config if you like) ──
        self._fcm_enabled: bool = 'fcm_service' in dir()
        self._sms_enabled: bool = 'sms_service' in dir()

    # ==================================================================
    # 1.  CORE — save in-app notification
    # ==================================================================
    def _save_notification(
        self,
        user_id: str,
        title: str,
        message: str,
        notification_type: str = 'general',
        data: Optional[Dict] = None,
    ) -> dict:
        """Persist a notification document in MongoDB."""
        doc = {
            'user_id': user_id,
            'title': title,
            'message': message,
            'type': notification_type,
            'data': data or {},
            'is_read': False,
            'created_at': datetime.utcnow(),
        }
        result = self.notifications.insert_one(doc)
        doc['_id'] = str(result.inserted_id)
        return doc

    # ==================================================================
    # 2.  PUSH — send FCM to a single user
    # ==================================================================
    def _send_push(
        self,
        user_id: str,
        title: str,
        body: str,
        data: Optional[Dict[str, str]] = None,
        notification_type: str = 'general',
    ) -> bool:
        """Look up the user's FCM token and fire a push notification."""
        if not self._fcm_enabled:
            return False
        try:
            user = self.users.find_one({'_id': ObjectId(user_id)})
            if not user:
                return False

            fcm_token = user.get('fcm_token')
            if not fcm_token:
                print(f"ℹ️  User {user_id} has no FCM token — push skipped.")
                return False

            return fcm_service.send_notification(
                fcm_token=fcm_token,
                title=title,
                body=body,
                data=data,
                notification_type=notification_type,
            )
        except Exception as e:
            print(f"❌ Push to {user_id} failed: {e}")
            return False

    # ==================================================================
    # 3.  SMS — alert emergency contacts of a patient
    # ==================================================================
    def _send_sms_to_contacts(
        self,
        patient_id: str,
        alert_type: str,
        details: str = '',
    ) -> Dict[str, int]:
        """Look up the patient's emergency_contacts and fire SMS."""
        if not self._sms_enabled:
            return {'success_count': 0, 'failure_count': 0, 'total': 0}

        try:
            patient = self.users.find_one({'_id': ObjectId(patient_id)})
            if not patient:
                return {'success_count': 0, 'failure_count': 0, 'total': 0}

            contacts = patient.get('emergency_contacts', [])
            patient_name = patient.get('full_name', 'A patient')

            if not contacts:
                print(f"ℹ️  Patient {patient_id} has no emergency contacts — SMS skipped.")
                return {'success_count': 0, 'failure_count': 0, 'total': 0}

            return sms_service.alert_emergency_contacts(
                contacts=contacts,
                patient_name=patient_name,
                alert_type=alert_type,
                details=details,
            )
        except Exception as e:
            print(f"❌ SMS alert for patient {patient_id} failed: {e}")
            return {'success_count': 0, 'failure_count': 0, 'total': 0}

    # ==================================================================
    #  HIGH-LEVEL API — call these from routes / services
    # ==================================================================

    def notify_user(
        self,
        user_id: str,
        title: str,
        message: str,
        notification_type: str = 'general',
        data: Optional[Dict] = None,
        send_push: bool = True,
    ) -> dict:
        """
        Send a notification to **one** user (in-app + optional push).

        Args:
            user_id:           Target user's ObjectId as string.
            title:             Short heading.
            message:           Notification body.
            notification_type: e.g. 'appointment', 'vitals_alert', 'connection'.
            data:              Extra payload dict.
            send_push:         Also send FCM push? (default True).

        Returns:
            The saved notification document.
        """
        # 1) In-app
        notif = self._save_notification(user_id, title, message, notification_type, data)

        # 2) Push
        if send_push:
            self._send_push(user_id, title, message, data, notification_type)

        return notif

    def notify_connected_doctors(
        self,
        patient_id: str,
        title: str,
        message: str,
        notification_type: str = 'patient_alert',
        data: Optional[Dict] = None,
        send_push: bool = True,
        send_sms_to_relatives: bool = False,
        sms_alert_type: str = 'health_alert',
        sms_details: str = '',
    ) -> Dict:
        """
        Notify **every doctor** connected to a patient.

        Flow:
            1. Look up all *active* connections for the patient.
            2. For each connected doctor → in-app + FCM push.
            3. Optionally SMS the patient's emergency contacts.

        Args:
            patient_id:            Patient ObjectId string.
            title:                 Notification heading.
            message:               Notification body.
            notification_type:     Category tag.
            data:                  Extra payload.
            send_push:             Send FCM push to each doctor?
            send_sms_to_relatives: Also SMS the patient's emergency contacts?
            sms_alert_type:        Label for the SMS (e.g. 'fall_detected').
            sms_details:           Extra detail text in the SMS.

        Returns:
            {
                'doctors_notified': int,
                'push_sent': int,
                'push_failed': int,
                'sms_result': {...}     # only if send_sms_to_relatives
            }
        """
        result: Dict = {
            'doctors_notified': 0,
            'push_sent': 0,
            'push_failed': 0,
        }

        # 1) Find active connections
        connections = list(self.connections.find({
            'patient_id': patient_id,
            'status': 'active',
        }))

        doctor_ids = [c['doctor_id'] for c in connections]

        # 2) Notify each doctor
        extra_data = dict(data or {})
        extra_data['patient_id'] = patient_id

        for doctor_id in doctor_ids:
            self._save_notification(doctor_id, title, message, notification_type, extra_data)
            result['doctors_notified'] += 1

            if send_push:
                ok = self._send_push(doctor_id, title, message, extra_data, notification_type)
                if ok:
                    result['push_sent'] += 1
                else:
                    result['push_failed'] += 1

        # 3) Optionally SMS relatives
        if send_sms_to_relatives:
            result['sms_result'] = self._send_sms_to_contacts(
                patient_id, sms_alert_type, sms_details
            )

        return result

    def notify_patient_from_doctor(
        self,
        doctor_id: str,
        patient_id: str,
        title: str,
        message: str,
        notification_type: str = 'doctor_message',
        data: Optional[Dict] = None,
        send_push: bool = True,
    ) -> dict:
        """
        A doctor sends a notification to one of their patients.
        """
        extra_data = dict(data or {})
        extra_data['doctor_id'] = doctor_id

        notif = self._save_notification(patient_id, title, message, notification_type, extra_data)

        if send_push:
            self._send_push(patient_id, title, message, extra_data, notification_type)

        return notif

    # ------------------------------------------------------------------
    #  Convenience shortcuts for common healthcare events
    # ------------------------------------------------------------------

    def send_emergency_alert(
        self,
        patient_id: str,
        alert_type: str,
        title: str = '',
        message: str = '',
        details: str = '',
        extra_data: Optional[Dict] = None,
    ) -> Dict:
        """
        🚨 EMERGENCY ALERT — triggers alarm-style notification on Flutter.

        Sends FCM push with  type='emergency'  so the Flutter frontend shows
        the full-screen / looping alarm notification (not just a normal banner).

        Also:
            • Saves in-app notification for every connected doctor.
            • SMS-alerts the patient's emergency contacts.

        Args:
            patient_id:  Patient ObjectId string.
            alert_type:  Short label (e.g. 'fall_detected', 'vitals_critical', 'sos').
            title:       Custom title (auto-generated if empty).
            message:     Custom body  (auto-generated if empty).
            details:     Extra info included in the SMS body.
            extra_data:  Any additional key/values for the FCM data payload.

        Returns:
            {
                'doctors_notified': int,
                'push_sent': int,
                'push_failed': int,
                'sms_result': {...},
            }
        """
        # Build default title/message if not provided
        if not title:
            title = f'🚨 EMERGENCY: {alert_type.replace("_", " ").title()}'
        if not message:
            message = f'Emergency alert for patient. Type: {alert_type}. {details}'.strip()

        data = dict(extra_data or {})
        data['alert_type'] = alert_type
        if details:
            data['details'] = details

        # Use notification_type='emergency' — this is what Flutter checks!
        return self.notify_connected_doctors(
            patient_id=patient_id,
            title=title,
            message=message,
            notification_type='emergency',      # ← triggers alarm on Flutter
            data=data,
            send_push=True,
            send_sms_to_relatives=True,         # always SMS for emergencies
            sms_alert_type=alert_type,
            sms_details=details,
        )

    def on_vitals_critical(self, patient_id: str, vitals_summary: str):
        """Patient's vitals crossed a critical threshold — EMERGENCY."""
        return self.send_emergency_alert(
            patient_id=patient_id,
            alert_type='vitals_critical',
            title='🚨 Critical Vitals Alert',
            message=f'Patient vitals need immediate attention: {vitals_summary}',
            details=vitals_summary,
        )

    def on_fall_detected(self, patient_id: str, location: str = ''):
        """Fall detection triggered for an elderly patient — EMERGENCY."""
        return self.send_emergency_alert(
            patient_id=patient_id,
            alert_type='fall_detected',
            title='🚨 Fall Detected',
            message=f'A fall has been detected. Location: {location or "unknown"}',
            details=f'Location: {location}' if location else '',
            extra_data={'location': location},
        )

    def on_medication_missed(self, patient_id: str, medication_name: str):
        """Patient missed a scheduled medication dose."""
        return self.notify_connected_doctors(
            patient_id=patient_id,
            title='💊 Medication Missed',
            message=f'Patient missed medication: {medication_name}',
            notification_type='medication_missed',
            data={'medication': medication_name},
            send_push=True,
            send_sms_to_relatives=False,  # not urgent enough for SMS by default
        )

    def on_appointment_reminder(self, patient_id: str, doctor_id: str, appointment_time: str):
        """Remind both patient and doctor about an upcoming appointment."""
        data = {
            'patient_id': patient_id,
            'doctor_id': doctor_id,
            'appointment_time': appointment_time,
        }
        # Notify patient
        self.notify_user(
            user_id=patient_id,
            title='📅 Appointment Reminder',
            message=f'You have an appointment at {appointment_time}',
            notification_type='appointment_reminder',
            data=data,
        )
        # Notify doctor
        self.notify_user(
            user_id=doctor_id,
            title='📅 Appointment Reminder',
            message=f'You have an appointment at {appointment_time}',
            notification_type='appointment_reminder',
            data=data,
        )

    def on_connection_request(self, patient_id: str, doctor_id: str, initiated_by: str):
        """A new connection request was created."""
        if initiated_by == 'patient':
            self.notify_user(
                user_id=doctor_id,
                title='🔗 New Connection Request',
                message='A patient has requested to connect with you.',
                notification_type='connection_request',
                data={'patient_id': patient_id},
            )
        else:
            self.notify_user(
                user_id=patient_id,
                title='🔗 New Connection Request',
                message='A doctor has requested to connect with you.',
                notification_type='connection_request',
                data={'doctor_id': doctor_id},
            )

    def on_connection_accepted(self, patient_id: str, doctor_id: str, accepted_by: str):
        """A connection request was accepted."""
        target_id = patient_id if accepted_by == 'doctor' else doctor_id
        self.notify_user(
            user_id=target_id,
            title='✅ Connection Accepted',
            message='Your connection request has been accepted!',
            notification_type='connection_accepted',
            data={'patient_id': patient_id, 'doctor_id': doctor_id},
        )
