import os
from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, send_from_directory, url_for

load_dotenv()

from .monitor import (
    add_whitelist_entry,
    clear_alerts,
    clear_reports,
    get_alerts,
    get_alerts_since,
    get_reports,
    get_reports_since,
    get_whitelist,
    remove_whitelist_entry,
    start_monitoring,
)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET', 'dev-key')


@app.route('/')
def index():
    reports = get_reports()
    alerts = get_alerts()
    whitelist = get_whitelist()
    return render_template('index.html', reports=reports, alerts=alerts, whitelist=whitelist)


@app.route('/style.css')
def legacy_style():
    return send_from_directory(app.static_folder, 'style.css')


@app.route('/api/alerts/clear', methods=['POST'])
def api_alerts_clear():
    data = request.get_json(silent=True) or {}
    type_filter = data.get('type')
    clear_alerts(type_filter)
    return jsonify({'success': True})


@app.route('/api/reports/clear', methods=['POST'])
def api_reports_clear():
    data = request.get_json(silent=True) or {}
    proto_filter = data.get('protocol')
    clear_reports(proto_filter)
    return jsonify({'success': True})


@app.route('/api/start')
def api_start():
    status = start_monitoring()
    return jsonify(status)


@app.route('/api/alerts')
def api_alerts():
    since = request.args.get('since', type=int)
    if since is not None:
        return jsonify({'alerts': get_alerts_since(since)})
    return jsonify({'alerts': get_alerts()})


@app.route('/api/reports')
def api_reports():
    since = request.args.get('since', type=int)
    if since is not None:
        return jsonify({'reports': get_reports_since(since)})
    return jsonify({'reports': get_reports()})


@app.route('/api/whitelist', methods=['GET', 'POST'])
def api_whitelist():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        ip = data.get('ip')
        mac = data.get('mac')
        note = data.get('note')
        try:
            key = add_whitelist_entry(ip, mac, note)
            return jsonify({'ok': True, 'key': key})
        except ValueError as e:
            return jsonify({'ok': False, 'error': str(e)}), 400
    return jsonify({'whitelist': get_whitelist()})


@app.route('/api/whitelist/remove', methods=['POST'])
def api_whitelist_remove():
    data = request.get_json(silent=True) or {}
    key = data.get('key')
    if not key:
        return jsonify({'ok': False, 'error': 'Falta key'}), 400
    remove_whitelist_entry(key)
    return jsonify({'ok': True})


if __name__ == '__main__':
    start_monitoring()
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes'),
        use_reloader=False,
    )
