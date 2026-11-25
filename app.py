"""Local dashboard. Run: python app.py  then open http://127.0.0.1:5001"""
import json
import os
import secrets
from pathlib import Path

from flask import (Flask, Response, abort, flash, redirect, render_template,
                   request, session, url_for)

from cloud.s3_upload import upload_report
from detector.parser import parse_email
from detector.report import sanitized_report
from detector.rules import analyze, load_config
from detector.store import Store


def create_app(db_path=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32),
                      MAX_CONTENT_LENGTH=1_000_000,
                      SESSION_COOKIE_SAMESITE="Strict")
    if db_path is None:
        Path("instance").mkdir(exist_ok=True)
        db_path = "instance/incidents.db"
    store = Store(db_path)
    config = load_config()

    def token():
        return session.setdefault("csrf", secrets.token_hex(16))

    app.jinja_env.globals["csrf_token"] = token

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            sent = request.form.get("csrf", "")
            if not secrets.compare_digest(sent, session.get("csrf", "") or "-"):
                abort(400, "Invalid form token. Reload the page.")

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def find(incident_id):
        return store.get(incident_id) or abort(404)

    @app.get("/")
    def index():
        return render_template("index.html", incidents=store.all(),
                               blocklist=store.blocklist())

    @app.post("/analyze")
    def upload():
        file = request.files.get("email")
        if not file or not file.filename.lower().endswith(".eml"):
            flash("Choose a .eml file.")
            return redirect(url_for("index"))
        email = parse_email(file.read())
        result = analyze(email, config, store.blocklist())
        return redirect(url_for("incident", incident_id=store.add(email, result)))

    @app.get("/incident/<incident_id>")
    def incident(incident_id):
        return render_template("incident.html", item=find(incident_id),
                               bucket=os.environ.get("REPORT_BUCKET"))

    @app.post("/incident/<incident_id>/action")
    def action(incident_id):
        find(incident_id)
        try:
            store.act(incident_id, request.form.get("action", ""),
                      request.form.get("note", "")[:500], config["trusted_domains"])
        except ValueError as error:
            flash(str(error))
        return redirect(url_for("incident", incident_id=incident_id))

    @app.get("/incident/<incident_id>/report")
    def report(incident_id):
        body = json.dumps(sanitized_report(find(incident_id)), indent=2)
        return Response(body, mimetype="application/json", headers={
            "Content-Disposition": f"attachment; filename=report-{incident_id}.json"})

    @app.post("/incident/<incident_id>/cloud")
    def cloud(incident_id):
        item = find(incident_id)
        bucket = os.environ.get("REPORT_BUCKET")
        if not bucket:
            flash("Set REPORT_BUCKET to enable cloud upload.")
        else:
            try:
                key = upload_report(sanitized_report(item), bucket)
                flash(f"Uploaded {key}")
            except Exception as error:  # show a safe message, not internals
                flash(f"Upload failed ({type(error).__name__}). Check AWS setup.")
        return redirect(url_for("incident", incident_id=incident_id))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5001, debug=False)
