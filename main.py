import os
import logging
import time
import re
import sys
import signal
from datetime import datetime
from dotenv import load_dotenv
from scraper import SMSHadiScraper
import telegram
from telegram import ParseMode

# Load config
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Config
USERNAME = os.getenv("SMS_PANEL_USERNAME")
PASSWORD = os.getenv("SMS_PANEL_PASSWORD")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHANNEL_ID = os.getenv("TELEGRAM_CHANNEL_ID")

if not all([USERNAME, PASSWORD, BOT_TOKEN, CHANNEL_ID]):
    logger.error("❌ Missing environment variables. Check .env file.")
    sys.exit(1)

# OTP Patterns (supports Arabic/English)
OTP_KEYWORDS = ["code", "otp", "verification", "password", "verify", "pin", "کود", "رمز", "کد"]
OTP_PATTERNS = [
    r'کود\s*[:\-]?\s*(\d{3}-\d{3})',
    r'کد\s*[:\-]?\s*(\d{3}-\d{3})',
    r'رمز\s*[:\-]?\s*(\d{3}-\d{3})',
    r'code\s*[:\-]?\s*(\d{3}-\d{3})',
    r'code\s+(\d{6})',
    r'(\d{3}-\d{3})',
    r'(\d{6})',
    r'OTP\s*[:\-]?\s*(\d+)',
]

SERVICE_MAPPINGS = {
    'whatsapp': 'WhatsApp', 'facebook': 'Facebook', 'google': 'Google',
    'telegram': 'Telegram', 'twitter': 'Twitter', 'instagram': 'Instagram',
    'bank': 'Bank', 'gmail': 'Gmail', 'yahoo': 'Yahoo',
    'واتساب': 'WhatsApp', 'وتساب': 'WhatsApp',
}

class OTPProcessor:
    def __init__(self):
        self.processed_otps = set()

    def is_otp_message(self, msg):
        if not msg: return False
        lower = msg.lower()
        has_kw = any(k in lower for k in OTP_KEYWORDS)
        has_pat = any(re.search(p, msg, re.IGNORECASE) for p in OTP_PATTERNS)
        return has_kw or has_pat

    def extract_otp_code(self, msg):
        for pattern in OTP_PATTERNS:
            match = re.search(pattern, msg, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def identify_service(self, cli, msg):
        cli_lower = cli.lower() if cli else ""
        msg_lower = msg.lower()
        for key, service in SERVICE_MAPPINGS.items():
            if key in cli_lower or key in msg_lower:
                return service
        return "Unknown Service"

    def normalize_phone_number(self, num):
        if not num or num == 'N/A': return "Number not available"
        cleaned = re.sub(r'[^\d+]', '', num)
        if not cleaned: return "Invalid number"
        if cleaned.startswith('880'): return f"+{cleaned}"
        if cleaned.startswith('0'): return f"+880{cleaned[1:]}"
        if len(cleaned) == 10: return f"+880{cleaned}"
        if len(cleaned) == 11 and cleaned.startswith('1'): return f"+88{cleaned}"
        return f"+{cleaned}" if not cleaned.startswith('+') else cleaned

    def format_timestamp(self, date_str):
        if not date_str or date_str == 'N/A': return "Time not available"
        formats = ['%Y-%m-%d %H:%M:%S', '%d/%m/%Y %H:%M']
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt).strftime("%B %d, %Y - %I:%M %p")
            except: pass
        return date_str

    def generate_message_id(self, data):
        return f"{data['number']}_{data['cli']}_{data['date']}"

    def process_message(self, data):
        if not self.is_otp_message(data['full_message']):
            return None
        msg_id = self.generate_message_id(data)
        if msg_id in self.processed_otps:
            return None
        otp = self.extract_otp_code(data['full_message'])
        if not otp:
            return None
        service = self.identify_service(data['cli'], data['full_message'])
        phone = self.normalize_phone_number(data['number'])
        time_fmt = self.format_timestamp(data['date'])
        result = {
            'message_id': msg_id,
            'service': service,
            'phone_number': phone,
            'otp_code': otp,
            'received_time': time_fmt,
            'full_message': data['full_message'],
        }
        self.processed_otps.add(msg_id)
        logger.info(f"✅ Processed OTP for {service}: {otp}")
        return result

class TelegramBot:
    def __init__(self, token, channel_id):
        self.bot = telegram.Bot(token=token)
        self.channel_id = channel_id

    def send_otp(self, data):
        message = f"""
🔐 **NEW OTP RECEIVED** 🔐
─────────────────────────────
**Service:** {data['service']}
**Phone Number:** `{data['phone_number']}`
**OTP Code:** `{data['otp_code']}`
**Received:** {data['received_time']}
**Full Message:** {data['full_message']}
**Status:** ✅ Active
─────────────────────────────
⚠️ **Security Warning:** Do not share this code with anyone
""".strip()
        try:
            self.bot.send_message(
                chat_id=self.channel_id,
                text=message,
                parse_mode=ParseMode.MARKDOWN,
                disable_web_page_preview=True
            )
            logger.info(f"📤 OTP sent for {data['service']}")
            return True
        except Exception as e:
            logger.error(f"❌ Telegram error: {e}")
            return False

class OTPForwarder:
    def __init__(self):
        self.scraper = SMSHadiScraper(USERNAME, PASSWORD)
        self.processor = OTPProcessor()
        self.telegram = TelegramBot(BOT_TOKEN, CHANNEL_ID)
        self.running = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        logger.info("🛑 Shutdown requested")
        self.running = False

    def run(self):
        logger.info("🚀 Starting OTP Forwarder...")
        if not self.scraper.login():
            logger.error("❌ Failed to login to panel")
            return

        self.running = True
        logger.info("🟢 Running. Press Ctrl+C to stop.")
        try:
            while self.running:
                messages = self.scraper.fetch_messages()
                for msg in messages:
                    otp_data = self.processor.process_message(msg)
                    if otp_
                        self.telegram.send_otp(otp_data)
                        time.sleep(1)
                if not messages:
                    logger.debug("📭 No new messages")
                for _ in range(10):  # Poll every 10 seconds
                    if not self.running:
                        break
                    time.sleep(1)
        finally:
            logger.info("🔴 Stopped")

if __name__ == "__main__":
    app = OTPForwarder()
    app.run()