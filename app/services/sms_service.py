"""
SMS Alert Service
=================
Handles sending SMS alerts to patient relatives / emergency contacts
via Twilio. Designed as a pluggable module — remove this file and its
import in notification_manager.py to disable SMS entirely.

Author: Cavista Team
Version: 1.0.0

Setup:
    pip install twilio
    Set these env variables:
        TWILIO_ACCOUNT_SID              – Your Twilio account SID
        TWILIO_AUTH_TOKEN               – Your Twilio auth token
        TWILIO_MESSAGING_SERVICE_SID    – Your Twilio Messaging Service SID
        SMS_ENABLED                     – Set to "true" to enable (default: false)
"""

import os
from typing import List, Optional, Dict


class SMSService:
    """
    SMS alerting service using Twilio.
    Singleton — only one instance is ever created.

    To **disable** SMS completely:
        • Set SMS_ENABLED=false in .env   (runtime toggle)
        • Or simply remove this file and its import in notification_manager.py
    """

    _instance = None
    _initialized = False
    _client = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SMSService, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        """Initialise Twilio client (only once)."""
        if not SMSService._initialized:
            self._enabled = os.getenv('SMS_ENABLED', 'false').lower() == 'true'

            if self._enabled:
                try:
                    from twilio.rest import Client  # lazy import so twilio is optional

                    account_sid = os.getenv('TWILIO_ACCOUNT_SID')
                    auth_token = os.getenv('TWILIO_AUTH_TOKEN')
                    self._messaging_service_sid = os.getenv('TWILIO_MESSAGING_SERVICE_SID')

                    if account_sid and auth_token and self._messaging_service_sid:
                        SMSService._client = Client(account_sid, auth_token)
                        print("✅ Twilio SMS service initialized")
                    else:
                        self._enabled = False
                        print("⚠️  SMS enabled but Twilio credentials are missing. SMS disabled.")
                        print("ℹ️  Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_MESSAGING_SERVICE_SID.")

                except ImportError:
                    self._enabled = False
                    print("⚠️  twilio package not installed. SMS disabled.")
                    print("ℹ️  Run: pip install twilio")

                except Exception as e:
                    self._enabled = False
                    print(f"⚠️  Twilio init failed: {e}")
            else:
                print("ℹ️  SMS service is disabled (SMS_ENABLED != true)")

            SMSService._initialized = True

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------
    @property
    def is_available(self) -> bool:
        """Return True when SMS service is ready to send."""
        return self._enabled and SMSService._client is not None

    # ------------------------------------------------------------------
    # Send single SMS
    # ------------------------------------------------------------------
    def send_sms(
        self,
        to_number: str,
        message: str,
    ) -> bool:
        """
        Send a single SMS.

        Args:
            to_number: Recipient phone number in E.164 format (e.g. +919876543210).
            message: SMS body text (max ~1600 chars).

        Returns:
            True on success, False otherwise.
        """
        try:
            if not self.is_available or not to_number:
                return False

            # Ensure number starts with +
            if not to_number.startswith('+'):
                to_number = f'+{to_number}'

            sms = SMSService._client.messages.create(
                messaging_service_sid=self._messaging_service_sid,
                body=message,
                to=to_number,
            )
            print(f"✅ SMS sent → SID: {sms.sid}, to: {to_number}")
            return True

        except Exception as e:
            print(f"❌ SMS send error ({to_number}): {e}")
            return False

    # ------------------------------------------------------------------
    # Send SMS to multiple numbers
    # ------------------------------------------------------------------
    def send_bulk_sms(
        self,
        phone_numbers: List[str],
        message: str,
    ) -> Dict[str, int]:
        """
        Send the same SMS message to a list of phone numbers.

        Returns:
            {'success_count': int, 'failure_count': int}
        """
        if not self.is_available or not phone_numbers:
            return {'success_count': 0, 'failure_count': len(phone_numbers or [])}

        success = 0
        failure = 0
        for number in phone_numbers:
            if self.send_sms(number, message):
                success += 1
            else:
                failure += 1

        return {'success_count': success, 'failure_count': failure}

    # ------------------------------------------------------------------
    # Healthcare-specific: alert emergency contacts
    # ------------------------------------------------------------------
    def alert_emergency_contacts(
        self,
        contacts: List[Dict],
        patient_name: str,
        alert_type: str,
        details: str = '',
    ) -> Dict[str, int]:
        """
        Send an emergency / health-event SMS to all emergency contacts.

        Args:
            contacts:     List of dicts like [{"name": "...", "phone": "...", "relationship": "..."}]
            patient_name: Name of the patient triggering the alert.
            alert_type:   Short label, e.g. 'fall_detected', 'vitals_critical'.
            details:      Extra info to include in the message body.

        Returns:
            {'success_count': int, 'failure_count': int, 'total': int}
        """
        if not self.is_available or not contacts:
            return {
                'success_count': 0,
                'failure_count': len(contacts or []),
                'total': len(contacts or []),
            }

        success = 0
        failure = 0

        for contact in contacts:
            phone = contact.get('phone') or contact.get('phone_number')
            name = contact.get('name', 'Family Member')
            relationship = contact.get('relationship', '')

            if not phone:
                failure += 1
                continue

            # Build a friendly message
            msg_lines = [
                f"🚨 HEALTH ALERT for {patient_name}",
                f"Type: {alert_type.replace('_', ' ').title()}",
            ]
            if details:
                msg_lines.append(f"Details: {details}")
            msg_lines.append(
                "Please check on them or contact their healthcare provider immediately."
            )
            message = '\n'.join(msg_lines)

            if self.send_sms(phone, message):
                success += 1
                print(f"  ↳ Alerted {name} ({relationship}) at {phone}")
            else:
                failure += 1

        return {
            'success_count': success,
            'failure_count': failure,
            'total': len(contacts),
        }


# Singleton instance
sms_service = SMSService()
