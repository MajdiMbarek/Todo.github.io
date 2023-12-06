import os
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Session(app)
db = SQLAlchemy(app)

if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Todo(db.Model):
    __tablename__ = 'todo'
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    todo_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)



@app.before_request
def create_tables():
    # Create all database tables when the application starts
    db.create_all()


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def todo():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            task = request.form.get("task")
            user_id = session["user_id"]

            new_task = Todo(task=task, todo_id=user_id)
            db.session.add(new_task)
            db.session.commit()

            return redirect(url_for("todo"))

        elif action == "delete":
            task_id = request.form.get("task_id")

            Todo.query.filter_by(id=task_id).delete()
            db.session.commit()

    user_id = session["user_id"]
    tasks = Todo.query.filter_by(todo_id=user_id).all()

    return render_template("todo.html", tasks=tasks)


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return apology("Must provide username and password", 403)

        user = User.query.filter_by(username=username).first()

        if user is None or not check_password_hash(user.password, password):
            return apology("Invalid username and/or password", 403)

        session["user_id"] = user.id
        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        if not username or not password:
            return apology("You should enter your username and a password", code="400")

        if password != confirm_password:
            return apology("Your password confirmation is incorrect")

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return apology("Username is not available")

        hash_password = generate_password_hash(password)
        new_user = User(username=username, password=hash_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect("/login")


def apology(message, code):
    pass


if __name__ == "__main__":
    app.run(debug=True)