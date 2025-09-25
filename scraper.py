import os
import requests
from bs4 import BeautifulSoup
import telegram
from telegram import ParseMode
import logging
import time
import re
import sys
import signal
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Suppress SSL warnings (only if using HTTP/insecure panel)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ==================== CONFIGURATION (from .env) ====================

SMS_PANEL_USERNAME = os.getenv("SMS_PANEL_USERNAME")
SMS_PANEL_PASSWORD = os.getenv("SMS_PANEL_PASSWORD")
PANEL_BASE_URL = "http://185.2.83.39"
LOGIN_URL = f"{PANEL_BASE_URL}/ints/login"
MESSAGES_URL = f"{PANEL_BASE_URL}/ints/agent/SMSCDRStats"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHANNEL_ID = os.getenv("TELEGRAM_CHANNEL_ID")

if not all([SMS_PANEL_USERNAME, SMS_PANEL_PASSWORD, TELEGRAM_BOT_TOKEN, TELEGRAM_CHANNEL_ID]):
    print("❌ Missing required environment variables. Check your .env file.")
    sys.exit(1)

# Application Configuration
POLLING_INTERVAL = 10  # seconds

# OTP Detection Patterns
OTP_KEYWORDS = ["code", "otp", "verification", "password", "verify", "pin"]
OTP_PATTERNS = [
    r'code\s+(\d{3}-\d{3})',
    r'code\s+(\d{6})',
    r'code\s+(\d{4})',
    r'OTP\s*[:\-]?\s*(\d+)',
    r'verification\s+code\s+(\d+)',
    r'(\d{3}-\d{3})',
    r'(\d{6})'
]

SERVICE_MAPPINGS = {
    'whatsapp': 'WhatsApp',
    'facebook': 'Facebook', 
    'google': 'Google',
    'telegram': 'Telegram',
    'twitter': 'Twitter',
    'instagram': 'Instagram',
    'bank': 'Bank',
    'gmail': 'Gmail',
    'yahoo': 'Yahoo'
}

# ==================== LOGGING SETUP ====================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# ==================== SMS SCRAPER CLASS ====================

class SMSHadiScraper:
    def __init__(self):
        self.session = requests.Session()
        self.is_logged_in = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0