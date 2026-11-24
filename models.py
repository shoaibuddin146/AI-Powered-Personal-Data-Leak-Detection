from field_crypto import EncryptedText
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from utils import mask_value
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(255))
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(255), nullable=False)
    notify_email = db.Column(db.Boolean, default=True)
    notify_sms = db.Column(db.Boolean, default=False)
    notify_push = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    monitored_items = db.relationship('MonitoredData', backref='user', lazy=True,
                                       cascade='all, delete-orphan')
    detections = db.relationship('Detection', backref='user', lazy=True,
                                  cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class MonitoredData(db.Model):
    __tablename__ = 'monitored_data'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    data_type = db.Column(db.String(50), nullable=False)  # email, phone, ssn, credit_card, password, api_key
    data_value = db.Column(EncryptedText(), nullable=False)
    label = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def display_value(self):
        return mask_value(self.data_type, self.data_value)


class Source(db.Model):
    __tablename__ = 'sources'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(500))
    source_type = db.Column(db.String(50))  # paste_site, forum, breach_db, mock
    is_active = db.Column(db.Boolean, default=True)


class ScrapedContent(db.Model):
    __tablename__ = 'scraped_content'

    id = db.Column(db.Integer, primary_key=True)
    source_name = db.Column(db.String(255))
    source_url = db.Column(db.String(500))
    content = db.Column(EncryptedText())
    scraped_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed = db.Column(db.Boolean, default=False)


class Detection(db.Model):
    __tablename__ = 'detections'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    monitored_data_id = db.Column(db.Integer, db.ForeignKey('monitored_data.id'), nullable=True)
    data_type = db.Column(db.String(50), nullable=False)
    matched_value = db.Column(EncryptedText(), nullable=False)
    source_url = db.Column(db.String(500))
    snippet = db.Column(EncryptedText())
    match_confidence = db.Column(db.Float, default=1.0)
    risk_level = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL
    is_read = db.Column(db.Boolean, default=False)
    is_resolved = db.Column(db.Boolean, default=False)
    source_name = db.Column(db.String(100))
    ai_summary = db.Column(db.Text)
    ai_action = db.Column(db.Text)
    ai_provider = db.Column(db.String(20))   # claude | local
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    detection_id = db.Column(db.Integer, db.ForeignKey('detections.id'), nullable=False)
    channel = db.Column(db.String(20))  # email, sms, push
    status = db.Column(db.String(20), default='sent')  # sent, failed, mock
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)


class SourceLog(db.Model):
    """Health of each live data source (shown on the dashboard)."""
    __tablename__ = 'source_logs'

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(100), index=True)
    status = db.Column(db.String(20))      # ok | rate_limited | error
    message = db.Column(db.String(500))
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
