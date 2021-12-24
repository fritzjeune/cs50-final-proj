
import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, make_response
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, set_access_cookies, unset_jwt_cookies, unset_access_cookies
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash, safe_str_cmp
from flask_session import Session
from datetime import datetime
import re

from notification import notification_message

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["JWT_SECRET_KEY"] = os.environ.get("SECRET")
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
app.config["JWT_COOKIE_SECURE"] = False
jwt = JWTManager(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///univhaiti.db")

# Make sure API key is set
if not os.environ.get("SECRET"):
    raise RuntimeError("SECRET not set")

@jwt.expired_token_loader
def my_unset_token_callback():
    return redirect("/login")

# @jwt.unset_access_cookies
# def my_expired_token_callback():
#     return redirect("/login"), 302

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/signup", methods=["POST", "PUT"])
def signup():
    email = request.form.get("email")
    password = request.form.get("password")
    password_comfirmation = request.form.get("conf-password")
    surname = request.form.get("surname")
    middle_name = request.form.get("middle-name")
    user_type = request.form.get("account-type")
    first_name = request.form.get("first-name")

    user = db.execute("SELECT * FROM users WHERE email =?", email)
    if email == "" or not validate("email", email):
        return notification_message("Invalid email", 403)
    elif password == "" or not validate("password", password):
        return notification_message("password blank or incorrect", 403)
    elif password != password_comfirmation:
        return notification_message("password and confirmation password not match", 403)
    elif len(user) > 0:
        return notification_message("Account already exist", 403)
    else: 
        hashed_pass = generate_password_hash(password)

        db.execute("INSERT INTO users (email, surname, middle_name, firstname, user_type, hash) VALUES (?,?,?,?,?,?)", email, surname, middle_name, first_name, user_type, hashed_pass)

        user = db.execute("SELECT id FROM users WHERE email=?", email)
        print(user)
        token = create_access_token(identity=user[0]["id"])
        db.execute("UPDATE users SET token =? WHERE email=?", token, email)
        response = make_response(redirect("/profil"), 302)
        set_access_cookies(response, token)
        return response

@app.route("/register/<user_type>", methods=["GET", "POST"])
@jwt_required()
def register(user_type):
    if request.method == "POST":
        pass
    else:
        current_user = get_jwt_identity()
        user = db.execute("SELECT * FROM users WHERE id=?", current_user)
        user[0]["hash"] = None
        user[0]["token"] = None
        # TODO pass only necessary info , but not the entire user obj
        if user_type == "student":  
            return render_template("/student-registration.html", user=user[0]), 201
        else: 
            return render_template("/institution-registration.html", user=user[0]), 201

@app.route("/profil", methods=["GET", "POST"])
@jwt_required()
def profil():
    if request.method == "POST":
        pass
    current_user = get_jwt_identity()
    print(current_user)
    user = db.execute("SELECT * FROM users WHERE id=?", current_user)
    user[0]["hash"] = None
    user[0]["token"] = None
    print(user)
    return render_template("profil.html", user=user[0]), 201

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = db.execute("SELECT * FROM users WHERE email =?", email)
        if email == "" or not validate("email", email):
            return notification_message("Invalid email", 403)
        elif password == "" or not check_password_hash(user[0]["hash"], password):
            return notification_message("password blank or incorrect", 403)
        else: 
            print(user)
            token = create_access_token(identity=user[0]["id"])
            print(token) 
            db.execute("UPDATE users SET token =? WHERE id=?", token, user[0]["id"])
            
            response = make_response(redirect("/profil"), 302)
            set_access_cookies(response, token)
            return response  
    return render_template("login.html")

@app.route("/logout", methods=["GET"])
def logout_with_cookies():
    response = make_response(redirect("/"), 302)
    unset_jwt_cookies(response)
    return response

def validate(type, text):
    # verify if user password contain uppercase , lowercase chars , numbers, and special chars   
    if type == "email":
        pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    else:
        pattern = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8}$")
    if pattern.match(text):
        return True
    else:
        return False

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return notification_message(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

    # def unset_jwt():
    # resp = make_response(redirect(app.config['BASE_URL'] + '/', 302))
    # unset_jwt_cookies(resp)
    # return resp