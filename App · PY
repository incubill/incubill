"""
Incubill — Flask backend with real accounts + subscription gating
====================================================================
This replaces the static-site version. Now the estimate tool itself is
only served to logged-in users whose subscription is active or in trial.

ARCHITECTURE CHANGE FROM THE STATIC VERSION
---------------------------------------------
- GitHub Pages can only serve static files, so it can no longer host the
  actual tool. This Flask app needs to run somewhere that executes Python
  (Render, Railway, Fly.io, etc.) — see DEPLOY.md for step-by-step Render
  instructions.
- Checkout now uses Dodo's real checkout_sessions.create API (server-side,
  with your secret API key) instead of the public static payment link,
  because we need to attach each checkout to a specific logged-in user
  (via customer email + metadata) so the webhook can update the right
  account when payment succeeds.
- A database now stores accounts and subscription status. This starter
  uses SQLite by default (fine for local development) but you should
  switch to Postgres for production — Render's free Postgres add-on works
  well. Just change DATABASE_URL in your .env.

SETUP
-----
1. Create a .env file (copy .env.example) with:
     SECRET_KEY=<random string>
     DODO_API_KEY=<your Dodo secret API key>
     DODO_ENVIRONMENT=test_mode   # or live_mode
     DODO_WEBHOOK_SECRET=<your Dodo webhook signing secret>
     DODO_PRODUCT_ID_MONTHLY=pdt_0NixvmMnNF6ocQBAHH4t5
     DODO_PRODUCT_ID_YEARLY=pdt_0Niznuz8H4ZBmVMPTpz3X
     BASE_URL=https://incubill.com   # or http://localhost:5000 for local dev
     DATABASE_URL=sqlite:///incubill.db
2. pip install -r requirements.txt
3. flask --app app init-db     (creates the database tables)
4. python app.py
5. In the Dodo Dashboard, point your webhook endpoint at:
     https://your-domain/webhook/dodo
   and copy the webhook signing secret into DODO_WEBHOOK_SECRET above.

WEBHOOK SIGNATURE VERIFICATION
-------------------------------
Dodo Payments follows the Standard Webhooks spec. This file verifies
signatures using the `standardwebhooks` package. Double-check the header
names and secret format against Dodo's current webhook docs in your
Dashboard (Settings -> Webhooks) — payment-provider webhook details can
change, and a mismatch here would either reject legitimate webhooks or
(worse) accept forged ones, so confirm this against the live docs before
going to production with real payments.
"""

import os
import datetime
from functools import wraps

from flask import Flask, render_template, redirect, request, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from dodopayments import DodoPayments

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///incubill.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # protects all POST forms (login, signup) automatically
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"])

login_manager = LoginManager(app)
login_manager.login_view = "login"

DODO_API_KEY = os.environ.get("DODO_API_KEY")
DODO_ENVIRONMENT = os.environ.get("DODO_ENVIRONMENT", "test_mode")
DODO_WEBHOOK_SECRET = os.environ.get("DODO_WEBHOOK_SECRET")
DODO_PRODUCT_ID_MONTHLY = os.environ.get("DODO_PRODUCT_ID_MONTHLY", "pdt_0NixvmMnNF6ocQBAHH4t5")
DODO_PRODUCT_ID_YEARLY = os.environ.get("DODO_PRODUCT_ID_YEARLY", "pdt_0Niznuz8H4ZBmVMPTpz3X")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")

dodo_client = DodoPayments(bearer_token=DODO_API_KEY, environment=DODO_ENVIRONMENT)


# ---------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Subscription state, kept in sync by the Dodo webhook.
    dodo_customer_id = db.Column(db.String(255), nullable=True)
    subscription_id = db.Column(db.String(255), nullable=True)
    subscription_status = db.Column(db.String(50), default="none")
    # Expected values: "none", "trialing", "active", "past_due", "canceled"
    plan = db.Column(db.String(20), nullable=True)  # "monthly" or "yearly"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_access(self):
        return self.subscription_status in ("trialing", "active")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("10 per hour")
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("signup.html")

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("signup.html")

        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for("subscribe"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user is None or not user.check_password(password):
            flash("Invalid email or password.", "error")
            return render_template("login.html")

        login_user(user)
        if user.has_access():
            return redirect(url_for("app_home"))
        return redirect(url_for("subscribe"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# Subscription gating
# ---------------------------------------------------------------------
def subscription_required(view_func):
    @wraps(view_func)
    @login_required
    def wrapped(*args, **kwargs):
        if not current_user.has_access():
            return redirect(url_for("subscribe"))
        return view_func(*args, **kwargs)
    return wrapped


@app.route("/subscribe")
@login_required
def subscribe():
    if current_user.has_access():
        return redirect(url_for("app_home"))
    return render_template("subscribe.html")


@app.route("/create-checkout/<plan>")
@login_required
def create_checkout(plan):
    product_id = DODO_PRODUCT_ID_YEARLY if plan == "yearly" else DODO_PRODUCT_ID_MONTHLY
    try:
        session = dodo_client.checkout_sessions.create(
            product_cart=[{"product_id": product_id, "quantity": 1}],
            customer={"email": current_user.email},
            metadata={"user_id": str(current_user.id)},
            return_url=f"{BASE_URL}/app",
        )
        return redirect(session.checkout_url)
    except Exception as exc:
        app.logger.error(f"Checkout session creation failed: {exc}")
        flash("Couldn't start checkout. Please try again in a moment.", "error")
        return redirect(url_for("subscribe"))


# ---------------------------------------------------------------------
# The actual tool — gated behind login + active/trialing subscription
# ---------------------------------------------------------------------
@app.route("/app")
@subscription_required
def app_home():
    return render_template("app.html", user=current_user)


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/")
def index():
    if current_user.is_authenticated and current_user.has_access():
        return redirect(url_for("app_home"))
    return redirect(url_for("login"))


# ---------------------------------------------------------------------
# Dodo webhook — this is what actually keeps subscription_status in sync
# ---------------------------------------------------------------------
@app.route("/webhook/dodo", methods=["POST"])
@csrf.exempt
def dodo_webhook():
    payload = request.get_data()
    headers = request.headers

    # Verify the webhook signature before trusting anything in the payload.
    # See the module docstring — confirm this against Dodo's current docs.
    try:
        from standardwebhooks.webhooks import Webhook
        wh = Webhook(DODO_WEBHOOK_SECRET)
        wh.verify(payload, {
            "webhook-id": headers.get("webhook-id", ""),
            "webhook-timestamp": headers.get("webhook-timestamp", ""),
            "webhook-signature": headers.get("webhook-signature", ""),
        })
    except Exception as exc:
        app.logger.warning(f"Webhook signature verification failed: {exc}")
        return jsonify({"error": "invalid signature"}), 400

    event = request.get_json(silent=True) or {}
    event_type = event.get("type", "")
    data = event.get("data", {})
    metadata = data.get("metadata", {}) or {}
    customer = data.get("customer", {}) or {}

    user = None
    if metadata.get("user_id"):
        user = db.session.get(User, int(metadata["user_id"]))
    if user is None and customer.get("email"):
        user = User.query.filter_by(email=customer["email"].lower()).first()

    if user is None:
        app.logger.warning(f"Webhook for unknown user: {event_type}")
        return jsonify({"status": "ignored, user not found"}), 200

    # Map Dodo's event types to our internal status. Confirm these exact
    # event type strings against the current Dodo webhook docs — this is
    # the part most likely to need adjusting as their API evolves.
    if event_type in ("subscription.active", "subscription.renewed"):
        user.subscription_status = "active"
        user.subscription_id = data.get("subscription_id")
        user.dodo_customer_id = customer.get("customer_id")
    elif event_type == "subscription.trialing":
        user.subscription_status = "trialing"
        user.subscription_id = data.get("subscription_id")
    elif event_type in ("subscription.cancelled", "subscription.expired"):
        user.subscription_status = "canceled"
    elif event_type == "payment.failed":
        user.subscription_status = "past_due"

    db.session.commit()
    return jsonify({"status": "processed"}), 200


# ---------------------------------------------------------------------
# CLI helper: `flask --app app init-db`
# ---------------------------------------------------------------------
@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Database tables created.")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
