"""Demo inputs for the presentation storyline (all fictitious)."""

DEMO_PASSWORD = "Samriddhi123"

DEMO_EMAIL = """From: "SBI Alerts" <alerts@sbi-kyc-update.xyz>
Reply-To: sbi.kyc.helpdesk@gmail.com
Subject: URGENT: Your KYC is pending - account will be blocked today

Dear Customer,

Your SBI account KYC update is pending. As per RBI guidelines your account will be suspended within 24 hours.
Click here to verify your account immediately and enter your net banking password and OTP:
http://sbi-kyc-update.xyz/login.php

Regards,
SBI KYC Team
"""

DEMO_URL = "http://sbi-kyc-update.xyz/login.php"

DEMO_APP = {"category": "Calculator", "permissions": ["INTERNET", "MICROPHONE", "SMS"]}

DEMO_DEVICE = {"os_updated": "YES", "auto_updates": "YES", "firewall": "YES", "antivirus": "YES", "screen_lock": "YES",
               "disk_encryption": "YES", "secure_boot": "YES", "mfa": "NO", "backup": "NO", "bluetooth": "YES",
               "public_wifi": "YES"}

DEMO_LEGIT_EMAIL = """From: Priya Sharma <priya@college.ac.in>
Subject: Project review moved to Friday

Hi team, the project review with our guide has moved to Friday 3 pm in Lab 2.
Please bring the updated architecture diagram. Thanks, Priya
"""

DEMO_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.flashlight.pro">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <uses-permission android:name="android.permission.RECEIVE_SMS"/>
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <application android:label="Flashlight Pro">
    <service android:name=".Helper" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"/>
  </application>
</manifest>
"""
