import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), "engine"))

from app import app, db
from ai_analyzer import check_api_key
from console import banner, log, mask_key
from scheduler import start_scheduler
from sources import build_sources

if __name__ == '__main__':
    banner('DATA LEAK DETECTOR - real-time monitor')
    cfg = app.config
    with app.app_context():
        db.create_all()
    log('CONFIG', f"mode={cfg['SCRAPER_MODE']}  scan every {cfg['SCAN_INTERVAL_MINUTES']} min  "
                  f"scheduler={'ON' if cfg['ENABLE_SCHEDULER'] else 'OFF'}")
    log('CONFIG', f"database: {cfg['SQLALCHEMY_DATABASE_URI']}")
    log('CONFIG', f"Claude key: {mask_key(cfg['ANTHROPIC_API_KEY'])}   GitHub token: "
                  f"{'set' if cfg['GITHUB_TOKEN'] else 'not set'}   "
                  f"Claude web search: {'ON' if cfg['AI_WEB_SEARCH'] else 'off'}")
    log('CONFIG', 'enabled sources: ' + ', '.join(s.name for s in build_sources(cfg)), 'ok')
    if cfg['ALLOW_CLOUD_AI_TRIAGE'] or cfg['AI_WEB_SEARCH']:
        check_api_key(cfg)  # only contact Anthropic when cloud functionality is explicitly enabled
    else:
        log('PRIVACY', 'Cloud AI disabled; local pipeline active. External breach APIs remain enabled.')
    start_scheduler(app)                     # use_reloader=False so it only starts once
    log('APP', 'open http://localhost:5000 in your browser (Ctrl+C to stop)', 'ok')
    app.run(debug=False, use_reloader=False, host='127.0.0.1', port=5000)
