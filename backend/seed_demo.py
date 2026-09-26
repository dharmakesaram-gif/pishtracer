import asyncio
from database.database import init_db
from main import app
from httpx import AsyncClient, ASGITransport

SAMPLE_EMAILS = [
    {
        "sender_name": "PayPal Fraud Alert",
        "sender_email": "security@verify-paypal-notice.com",
        "subject": "CRITICAL: Unauthorized login attempt from Nigeria",
        "body_text": "Dear customer, we detected an unauthorized login to your account. Your account has been temporarily locked. Verify your identity immediately or your funds will be frozen. Click here to confirm identity: http://185.220.101.1/login. Wire transfer cancellation fee applies.",
        "raw_headers": "From: PayPal Fraud Alert <security@verify-paypal-notice.com>\nReturn-Path: <bounce@campaign-fast-track.net>\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail\nReceived: from 185.220.101.1 by mx.google.com"
    },
    {
        "sender_name": "Microsoft 365 Admin",
        "sender_email": "support@msoft-update-center.org",
        "subject": "Urgent Action Required: Password expires in 2 hours",
        "body_text": "Dear User, your Microsoft 365 organization password is set to expire today. Immediate action required. Failure to update will result in termination of mailbox access. Update now at http://185.220.101.2/ms-login or verify identity.",
        "raw_headers": "From: Microsoft 365 Admin <support@msoft-update-center.org>\nReturn-Path: <admin@msoft-update-center.org>\nAuthentication-Results: spf=softfail; dkim=fail; dmarc=fail\nReceived: from 185.220.101.2 by mx.google.com"
    },
    {
        "sender_name": "Amazon Customer Care",
        "sender_email": "billing@amazon-shipment-tracker.biz",
        "subject": "Invoice attached: Order #983-4921948 confirmed ($1,299.00)",
        "body_text": "Thank you for your order! Your credit card has been charged $1,299.00 for Apple iPhone 15 Pro. If you did not make this purchase, call support or visit link immediately: bit.ly/cancel-amazon-charge. Gift card refund available.",
        "raw_headers": "From: Amazon Customer Care <billing@amazon-shipment-tracker.biz>\nReturn-Path: <spoof@bulletproof-vps.ru>\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail\nReceived: from 93.184.216.34 by mx.google.com"
    },
    {
        "sender_name": "HDFC Bank NetBanking",
        "sender_email": "alerts@hdfc-ebanking-secure.in",
        "subject": "KYC Mandate: Update PAN and Aadhaar details immediately",
        "body_text": "Dear Customer, RBI mandate requires immediate re-verification of KYC. Your net banking access will be suspended within 24 hours. Click here to verify PAN: http://192.168.1.50/hdfc-kyc. Enter OTP and confidential PIN.",
        "raw_headers": "From: HDFC Bank NetBanking <alerts@hdfc-ebanking-secure.in>\nReturn-Path: <alerts@hdfc-ebanking-secure.in>\nAuthentication-Results: spf=pass; dkim=fail; dmarc=fail\nReceived: from 103.25.12.8 by mx.google.com"
    },
    {
        "sender_name": "Google Workspace Support",
        "sender_email": "no-reply@accounts.google.com",
        "subject": "Security Alert: New sign-in from Chrome on Windows",
        "body_text": "Your Google Account was just signed in to from a new Windows device. If this was you, you don't need to do anything. If this wasn't you, review your recent activity at https://myaccount.google.com/notifications.",
        "raw_headers": "From: Google <no-reply@accounts.google.com>\nReturn-Path: <3xK54WxA-Google@notifications.google.com>\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\nReceived: from 209.85.220.41 by mx.google.com"
    },
    {
        "sender_name": "GitHub Notifications",
        "sender_email": "notifications@github.com",
        "subject": "[GitHub] A personal access token has expired",
        "body_text": "Hi @dharma, your personal access token 'deploy-token' has expired. You can regenerate or view your tokens in your GitHub account settings at https://github.com/settings/tokens.",
        "raw_headers": "From: GitHub <notifications@github.com>\nReturn-Path: <noreply@github.com>\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\nReceived: from 140.82.112.4 by mx.google.com"
    }
]

async def seed():
    await init_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        print("Seeding sample threat emails into database...")
        for sample in SAMPLE_EMAILS:
            res = await client.post("/api/analyze", json=sample)
            if res.status_code == 200:
                data = res.json()
                print(f" [+] {data.get('risk_level')} ({data.get('risk_score')}/100) - {sample['subject'][:45]}...")
            else:
                print(f" [!] Error: {res.status_code} - {res.text}")
        print("\nSeeding complete! Check /api/stats and /api/campaigns")

if __name__ == "__main__":
    asyncio.run(seed())
