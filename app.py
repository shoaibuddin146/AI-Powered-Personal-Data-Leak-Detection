import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "engine"))

import os
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import (
    LoginManager, login_user, logout_user, login_required, current_user
)

from config import Config
from input_validation import validate_monitor_value
from safe_pii import valid_ssn, valid_sin
from detectors.pii_detector import luhn_check
from models import db, User, MonitoredData, Detection, SourceLog, Alert
from live_scanner import run_scan
from scan_options import ScanOptions
from utils import sha1_upper, is_sha1_hex, digits_only, mask_value

app = Flask(__name__)
app.config.from_object(Config)

# Ensure instance folder exists for SQLite
os.makedirs(os.path.join(app.root_path, 'instance'), exist_ok=True)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --------------------------------------------------------------------------
# Public routes
# --------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()

        if not email or not password:
            flash('Email and password are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('An account with that email already exists.', 'error')
            return redirect(url_for('register'))

        user = User(email=email, full_name=full_name, phone=phone)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash('Account created successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# --------------------------------------------------------------------------
# Authenticated routes
# --------------------------------------------------------------------------


ALLOWED_TYPES = {'email', 'phone', 'ssn', 'sin', 'credit_card', 'password', 'api_key', 'domain'}


def _latest_sources():
    """Most recent status of each live data source."""
    seen, out = set(), []
    for row in SourceLog.query.order_by(SourceLog.checked_at.desc()).limit(60):
        if row.source not in seen:
            seen.add(row.source)
            out.append({'name': row.source, 'status': row.status, 'message': row.message,
                        'checked_at': row.checked_at.strftime('%H:%M:%S')})
    return out


def _stats_for(user):
    q = Detection.query.filter_by(user_id=user.id)
    return {
        'total_monitored': MonitoredData.query.filter_by(user_id=user.id).count(),
        'total_detections': q.count(),
        'unread_detections': q.filter_by(is_read=False).count(),
        'critical_detections': q.filter_by(risk_level='CRITICAL').count(),
    }


@app.route('/api/stats')
@login_required
def api_stats():
    """Polled by the dashboard every few seconds for live updates."""
    recent = (Detection.query.filter_by(user_id=current_user.id)
              .order_by(Detection.detected_at.desc()).limit(5).all())
    return jsonify({
        'stats': _stats_for(current_user),
        'recent': [{'id': d.id, 'risk': d.risk_level, 'type': d.data_type,
                    'matched': mask_value(d.data_type, d.matched_value)[:50],
                    'detected_at': d.detected_at.strftime('%Y-%m-%d %H:%M')} for d in recent],
        'sources': _latest_sources(),
    })


@app.route('/dashboard')
@login_required
def dashboard():
    stats = {
        'total_monitored': MonitoredData.query.filter_by(user_id=current_user.id).count(),
        'total_detections': Detection.query.filter_by(user_id=current_user.id).count(),
        'unread_detections': Detection.query.filter_by(user_id=current_user.id, is_read=False).count(),
        'critical_detections': Detection.query.filter_by(
            user_id=current_user.id, risk_level='CRITICAL'
        ).count(),
    }
    recent_detections = (
        Detection.query.filter_by(user_id=current_user.id)
        .order_by(Detection.detected_at.desc())
        .limit(5)
        .all()
    )
    return render_template('dashboard.html', stats=stats, recent_detections=recent_detections,
                           user=current_user, sources=_latest_sources())


@app.route('/monitor', methods=['GET', 'POST'])
@login_required
def monitor():
    if request.method == 'POST':
        data_type = request.form.get('data_type')
        data_value = request.form.get('data_value', '').strip()
        label = request.form.get('label', '').strip()

        if data_type not in ALLOWED_TYPES or not data_value:
            flash('Choose a valid data type and enter a value.', 'error')
            return redirect(url_for('monitor'))

        data_value, validation_error = validate_monitor_value(data_type, data_value)
        if validation_error:
            flash(validation_error, 'error')
            return redirect(url_for('monitor'))

        # Identity and payment numbers are checked locally and never passed to external sources.
        if data_type in ('ssn', 'sin', 'credit_card'):
            from console import log
            from utils import digits_only
            digits = digits_only(data_value)
            if data_type == 'credit_card':
                valid = 13 <= len(digits) <= 19 and luhn_check(digits)
            elif data_type == 'ssn':
                valid = len(digits) == 9 and valid_ssn(f'{digits[:3]}-{digits[3:5]}-{digits[5:]}')
            else:
                valid = valid_sin(digits)
            if not valid:
                flash('The value did not pass local format validation. Nothing was saved.', 'error')
                log('LOCAL', f'{data_type}: local format validation failed. Value not logged.', 'warn')
                return redirect(url_for('monitor'))
            # Compare against synthetic research data before discarding the full value.
            # This is not a live card/identity breach lookup.
            from number_exposure import check_demo_exposure
            demo_source = check_demo_exposure(data_type, digits)
            if data_type == 'credit_card':
                from card_exposure_provider import check_real_card_exposure
                external = check_real_card_exposure(digits)
                log('EXPOSURE', f'Credit card real-world exposure: {external.status}. {external.detail}')
            if demo_source:
                log('DETECTION', f'{data_type}: synthetic exposure match in {demo_source}. Not a verified public breach.', 'warn')
                flash(f'Validation passed. Synthetic exposure match: {demo_source}. Real-world exposure: NOT AVAILABLE (no authorized provider).', 'warning')
            else:
                log('LOCAL', f'{data_type}: local format validation passed. No synthetic exposure match. Real-world exposure not checked.')
                flash('Validation passed. No synthetic dataset match. Real-world exposure: NOT AVAILABLE (no authorized provider).', 'warning')
            # Retain only the last four digits. Full PAN/identity numbers are never persisted.
            data_value = '****' + digits[-4:]

        # Normalise / protect the stored value
        if data_type == 'email' or data_type == 'domain':
            data_value = data_value.lower()
        elif data_type == 'password':
            # Never store the plaintext: keep only the SHA-1 (what the k-anonymity check needs)
            data_value = data_value.upper() if is_sha1_hex(data_value) else sha1_upper(data_value)
        elif data_type in ('ssn', 'credit_card'):
            data_value = digits_only(data_value)

        if any(i.data_value == data_value for i in MonitoredData.query.filter_by(
                user_id=current_user.id, data_type=data_type).all()):
            flash('You are already monitoring that value.', 'error')
            return redirect(url_for('monitor'))

        db.session.add(MonitoredData(user_id=current_user.id, data_type=data_type,
                                     data_value=data_value, label=label))
        db.session.commit()
        if data_type in ('ssn', 'sin', 'credit_card'):
            flash('Masked reference saved. Number validation and synthetic comparison were completed locally; no recurring real-world number lookup is available.', 'success')
        else:
            flash('Item added to monitoring list. It will be checked on the next scan.', 'success')
        return redirect(url_for('monitor'))

    monitored_items = MonitoredData.query.filter_by(user_id=current_user.id).order_by(
        MonitoredData.created_at.desc()
    ).all()
    return render_template('monitor.html', monitored_items=monitored_items)


@app.route('/monitor/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_monitored(item_id):
    item = MonitoredData.query.filter_by(id=item_id, user_id=current_user.id).first_or_404()
    # Remove all findings and their alerts for this monitored item.
    # Otherwise old results remain visible after monitoring is stopped.
    related = Detection.query.filter_by(user_id=current_user.id, monitored_data_id=item.id).all()
    for finding in related:
        Alert.query.filter_by(user_id=current_user.id, detection_id=finding.id).delete(synchronize_session=False)
        db.session.delete(finding)
    db.session.delete(item)
    db.session.commit()
    flash(f'Item removed. {len(related)} related detection(s) and their alerts were also removed.', 'success')
    return redirect(url_for('monitor'))


@app.route('/detections')
@login_required
def detections():
    risk_filter = request.args.get('risk', '')
    page = request.args.get('page', 1, type=int)

    query = Detection.query.filter_by(user_id=current_user.id)
    if risk_filter:
        query = query.filter_by(risk_level=risk_filter)

    pagination = query.order_by(Detection.detected_at.desc()).paginate(page=page, per_page=10)
    return render_template('detections.html', detections=pagination, risk_filter=risk_filter)


@app.route('/detections/<int:detection_id>')
@login_required
def detection_detail(detection_id):
    detection = Detection.query.filter_by(id=detection_id, user_id=current_user.id).first_or_404()
    if not detection.is_read:
        detection.is_read = True
        db.session.commit()
    return render_template('detection_detail.html', detection=detection)


@app.route('/detections/<int:detection_id>/resolve', methods=['POST'])
@login_required
def resolve_detection(detection_id):
    detection = Detection.query.filter_by(id=detection_id, user_id=current_user.id).first_or_404()
    detection.is_resolved = True
    db.session.commit()
    flash('Detection marked as resolved.', 'success')
    return redirect(url_for('detection_detail', detection_id=detection_id))


@app.route('/scan', methods=['POST'])
@login_required
def scan():
    """Manual scan of the current user's data (the scheduler does this automatically)."""
    result = run_scan(app, current_user.id, trigger='manual dashboard', options=ScanOptions.from_form(request.form, app.config))
    if result['busy']:
        flash('A scan is already running - try again in a moment.', 'warning')
    elif result['new_detections']:
        flash(f"Scan complete: {result['new_detections']} new detection(s) found.", 'warning')
    else:
        flash('Scan complete: no new detections. Existing results may still be listed.', 'success')
    bad = [n for n, st in result['sources'].items() if st != 'ok']
    if bad:
        flash('Some sources had problems: ' + ', '.join(bad) + ' (see source status below).', 'warning')
    return redirect(url_for('dashboard'))


# --------------------------------------------------------------------------
# CLI commands
# --------------------------------------------------------------------------

@app.cli.command('scan-now')
def scan_now():
    """Scan every user once (flask scan-now) - handy for cron."""
    print(run_scan(app, trigger='cli'))


@app.cli.command('init-db')
def init_db():
    """Initialize the database (flask init-db)."""
    with app.app_context():
        db.create_all()
    print('Database initialized.')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
