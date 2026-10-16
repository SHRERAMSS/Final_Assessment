import sqlite3
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "student-profile-portal-key"
app.config["DATABASE"] = Path(app.root_path) / "students.db"


class Student:
    fields = ("id", "name", "email", "age", "gender", "course", "password")

    def connect(self):
        connection = sqlite3.connect(app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self):
        with self.connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    age INTEGER NOT NULL,
                    gender TEXT NOT NULL,
                    course TEXT NOT NULL,
                    password TEXT NOT NULL
                )"""
            )

    def by_email(self, email):
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM students WHERE email = ?", (email,)
            ).fetchone()

    def by_id(self, student_id):
        with self.connect() as connection:
            return connection.execute(
                "SELECT * FROM students WHERE id = ?", (student_id,)
            ).fetchone()


student_db = Student()
student_db.initialize()


@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        age_text = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()
        course = request.form.get("course", "").strip()
        password = request.form.get("password", "")

        if not all((name, email, age_text, gender, course, password)):
            flash("Please complete every field.", "error")
            return render_template("register.html")
        if not age_text.isdigit() or int(age_text) < 1:
            flash("Please enter a valid numeric age.", "error")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
            return render_template("register.html")

        try:
            with student_db.connect() as connection:
                cursor = connection.execute(
                    """INSERT INTO students (name, email, age, gender, course, password)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (name, email, int(age_text), gender, course, generate_password_hash(password)),
                )
                session["student_id"] = cursor.lastrowid
        except sqlite3.IntegrityError:
            flash("That email is already registered. Please log in.", "error")
            return render_template("register.html")
        except sqlite3.Error:
            flash("Registration could not be saved. Please try again.", "error")
            return render_template("register.html")

        return redirect(url_for("success"))

    return render_template("register.html")


@app.route("/success")
def success():
    if "student_id" not in session:
        return redirect(url_for("login"))
    student = student_db.by_id(session["student_id"])
    if student is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template("success.html", name=student["name"])


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        student = student_db.by_email(request.form.get("email", "").strip().lower())
        password = request.form.get("password", "")
        if student and check_password_hash(student["password"], password):
            session["student_id"] = student["id"]
            return redirect(url_for("profile"))
        flash("Email or password is incorrect.", "error")
    return render_template("login.html")


@app.route("/profile")
def profile():
    student_id = session.get("student_id")
    if student_id is None:
        return redirect(url_for("login"))
    student = student_db.by_id(student_id)
    if student is None:
        session.clear()
        return redirect(url_for("login"))
    return render_template("profile.html", student=student)


@app.route("/update-course", methods=["POST"])
def update_course():
    student_id = session.get("student_id")
    course = request.form.get("course", "").strip()
    allowed_courses = {"Computer Science", "Business", "Design", "Engineering", "Data Science"}
    if student_id is None:
        return jsonify(error="Please log in again."), 401
    if course not in allowed_courses:
        return jsonify(error="Please choose a valid course."), 400
    try:
        with student_db.connect() as connection:
            result = connection.execute(
                "UPDATE students SET course = ? WHERE id = ?", (course, student_id)
            )
        if result.rowcount == 0:
            return jsonify(error="Student account was not found."), 404
    except sqlite3.Error:
        return jsonify(error="Course could not be updated."), 500
    return jsonify(message=f"Course updated to: {course}", course=course)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
