import os
from dotenv import load_dotenv

load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-this-in-production')

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(basedir, 'instance', 'data_leak_detector.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email alerts (SMTP) - leave blank to run in MOCK mode (alerts just get logged/printed)
    MAIL_SERVER = os.environ.get('MAIL_SERVER', '')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'alerts@dataleakdetector.local')

    # Detection engine
    FUZZY_MATCH_THRESHOLD = float(os.environ.get('FUZZY_MATCH_THRESHOLD', 0.85))

    # Data sources: 'live' = free real APIs, 'mock' = offline synthetic data, 'both' = mix
    SCRAPER_MODE = os.environ.get('SCRAPER_MODE', 'live')   # live | mock | both

    # Real-time scanning
    ENABLE_SCHEDULER = os.environ.get('ENABLE_SCHEDULER', 'true').lower() == 'true'
    SCAN_INTERVAL_MINUTES = int(os.environ.get('SCAN_INTERVAL_MINUTES', 30))
    FEED_LOOKBACK_DAYS = int(os.environ.get('FEED_LOOKBACK_DAYS', 90))

    # Optional keys (everything works without them)
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
    ANTHROPIC_MODEL = os.environ.get('ANTHROPIC_MODEL', 'claude-haiku-5-5')
    # Real-time web search done BY Claude with your key (costs credits; sends email/domain to Anthropic)
    ALLOW_CLOUD_AI_TRIAGE = os.environ.get('ALLOW_CLOUD_AI_TRIAGE', 'false').lower() == 'true'
    PHONE_WEB_SEARCH = os.environ.get('PHONE_WEB_SEARCH', 'false').lower() == 'true'
    AI_WEB_SEARCH = os.environ.get('AI_WEB_SEARCH', 'false').lower() == 'true'  # Opt-in: may send monitored identifiers to Anthropic
    ANTHROPIC_SEARCH_MODEL = os.environ.get('ANTHROPIC_SEARCH_MODEL', 'claude-sonnet-5-5')
