from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

DB_NAME = "database.db"


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp TEXT NOT NULL,
            expiry_time TEXT NOT NULL,
            is_used INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (name, email, username, password) VALUES (?, ?, ?, ?)",
                (name, email, username, hashed_password)
            )
            conn.commit()
            conn.close()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email or username already exists.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username, username)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            otp = str(random.randint(100000, 999999))
            expiry_time = datetime.now() + timedelta(minutes=5)

            conn.execute(
                "INSERT INTO otps (user_id, otp, expiry_time, is_used) VALUES (?, ?, ?, 0)",
                (user["id"], otp, expiry_time.isoformat())
            )
            conn.commit()
            conn.close()

            session["temp_user_id"] = user["id"]

            # Demo purpose: OTP shown on next page.
            # In real project, send OTP to email instead.
            session["demo_otp"] = otp
            print("Your OTP is:", otp)

            return redirect(url_for("verify_otp"))
        else:
            conn.close()
            flash("Invalid username/email or password.", "danger")

    return render_template("login.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "temp_user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["temp_user_id"]

    if request.method == "POST":
        entered_otp = request.form["otp"]

        conn = get_db()
        otp_record = conn.execute("""
            SELECT * FROM otps 
            WHERE user_id = ? AND otp = ? AND is_used = 0
            ORDER BY id DESC LIMIT 1
        """, (user_id, entered_otp)).fetchone()

        if otp_record:
            expiry_time = datetime.fromisoformat(otp_record["expiry_time"])

            if datetime.now() <= expiry_time:
                conn.execute("UPDATE otps SET is_used = 1 WHERE id = ?", (otp_record["id"],))
                conn.commit()
                conn.close()

                session.pop("temp_user_id", None)
                session.pop("demo_otp", None)
                session["user_id"] = user_id

                return redirect(url_for("dashboard"))
            else:
                conn.close()
                flash("OTP expired. Please login again.", "danger")
                return redirect(url_for("login"))
        else:
            conn.close()
            flash("Invalid OTP.", "danger")

    return render_template("verify_otp.html", demo_otp=session.get("demo_otp"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()

    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    create_tables()
    app.run(debug=True)
