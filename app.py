
import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, make_response
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, set_access_cookies, unset_jwt_cookies, unset_access_cookies
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash, safe_str_cmp
from werkzeug.utils import secure_filename
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
import re

from notification import notification_message

# Configure application
app = Flask(__name__)
csrf = CSRFProtect(app)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["JWT_SECRET_KEY"] = os.environ.get("SECRET")
app.config["SECRET_KEY"] = "Mar$19ly"  # change it before submit 
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_COOKIE_SECURE"] = False
jwt = JWTManager(app)

UPLOAD_FOLDER = './static/imgs'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///univhaiti.db")

# Make sure API key is set
if not os.environ.get("SECRET"):
    raise RuntimeError("SECRET not set")

def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# @jwt.expired_token_loader()
# def my_unset_token_callback():
#     return redirect("/login")

# @jwt.unset_access_cookies
# def my_expired_token_callback():
#     return redirect("/login"), 302

@app.route("/", methods=["GET"])
# @csrf.exempt
def index():
    return render_template("index.html")

@app.route("/upload/profil/<user_id>", methods=["POST"])
@csrf.exempt
@jwt_required()
def upload_pic(user_id):
    if request.method == "POST":
        current_user = get_jwt_identity()

        if int(user_id) != current_user:
            return {
                "success": False,
                "msg": "You are not autorized to perform this action",
                "code": 401
            }
        # print(request.files["file"])    

        if 'file' not in request.files:
            # flash('No file part')
            return {
                "success": False,
                "msg": "Please include file",
                "code": 402
            }
        file = request.files['file']
        if file == "":
            return {
                "success": False,
                "msg": "Please include file",
                "code": 403
            }
        

        if file and allowed_file(file.filename):
                # TODO get the file extention...
                filename = "profil_img" + str(current_user) + ".jpg"
                print(filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        db.execute("UPDATE users SET img_path=? WHERE id=?", filename, current_user)
        return {
                "success": True,
                "msg": "File uploaded successfuly",
                "code": 200
            }

@app.route("/institutions", methods=["GET"])
def get_institution():
    rows = db.execute("SELECT * FROM universities")
    return render_template("/institution-page.html", rows=rows)



@app.route("/signup", methods=["POST", "PUT"])
# @csrf.exempt
def signup():
    email = request.form.get("email")
    password = request.form.get("password")
    password_comfirmation = request.form.get("conf-password")
    surname = request.form.get("surname")
    username = request.form.get("username")
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

        db.execute("INSERT INTO users (username, email, surname, middle_name, firstname, user_type, hash) VALUES (?,?,?,?,?,?,?)",username, email, surname, middle_name, first_name, user_type, hashed_pass)

        user = db.execute("SELECT id FROM users WHERE email=?", email)
        print(user)
        token = create_access_token(identity=user[0]["id"])
        db.execute("UPDATE users SET token =? WHERE email=?", token, email)
        response = make_response(redirect("/profil"), 302)
        set_access_cookies(response, token)
        return response

@app.route("/register/<user_type>", methods=["GET", "POST"])
@csrf.exempt
@jwt_required()
def register(user_type):
    current_user = get_jwt_identity()
    user = db.execute("SELECT * FROM users WHERE id=?", current_user)[0]
    if request.method == "POST":
        if user_type == "student":
            pass
        elif user_type == "institution":
            data = request.form
            inst_type = data.get("institution-type")
            inst_owner = data.get("institution-owner")
            other_inst_type = data.get("other-inst-type")
            inst_name = data.get("name")
            inst_bis_name = data.get("business-name")
            inst_patente = data.get("patente")
            inst_menfp_id = data.get("menfp-id")
            inst_min_com_id = data.get("min-com-id")
            inst_edu_field = data.get("educational-field")
            inst_specialisation = data.get("specialisation")
            inst_founded_year = data.get("founded-year")
            inst_director = data.get("director")
            inst_have_campus = data.get("have-camp")
            inst_have_fac = data.get("have-fac")

            if inst_have_campus.lower() == "off" or inst_have_campus == None:
                inst_have_campus = 0
            else: 
                inst_have_campus = 1

            if inst_have_fac.lower() == "off" or inst_have_fac == None:
                inst_have_fac = 0
            else:
                inst_have_fac = 1
            
            if inst_founded_year != "": 
                inst_founded_year  = int(inst_founded_year)
            else: 
                inst_founded_year = None

            if inst_type == "other": 
                inst_type = other_inst_type
            try:
                new_univ = db.execute("INSERT INTO universities (user_author_id, name, business_name, min_commerce_id, patente, founded_year, academic_sector, menfp_code, director_name, have_campus, have_fac, institution_type, institution_owner, specialisations) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", 
                user["id"], inst_name, inst_bis_name, inst_min_com_id, inst_patente, inst_founded_year, inst_edu_field, inst_menfp_id, inst_director, inst_have_campus, inst_have_fac, inst_type, inst_owner, inst_specialisation)
            except:
                return redirect(request.url) , 302
            

            print(new_univ)
            return redirect("/profil") , 302

    else:
        user["hash"] = None
        user["token"] = None
        # TODO pass only necessary info , but not the entire user obj
        if user_type == "student":  
            return render_template("/student-registration.html", user=user), 201
        else: 
            return render_template("/institution-basic-info.html", user=user), 201


@app.route("/<referense_id>/address", methods=["GET", "POST"])
@jwt_required()
def add_address():
    current_user = get_jwt_identity()
    user = db.execute("SELECT * FROM users WHERE id=?", current_user)[0]
    if request.method == "POST":
        pass
    return render_template("address.html", user=user)

@app.route("/profil", methods=["GET", "POST"])
@jwt_required()
def profil():
    if request.method == "POST":
        pass
    current_user = get_jwt_identity()
    # print(current_user)
    user = db.execute("SELECT * FROM users WHERE id=?", current_user)[0]
    user["hash"] = None
    user["token"] = None
    if user["user_type"] == "student":
        rows = db.execute("SELECT * FROM students WHERE user_id=?", current_user)
    else:
        rows = db.execute("SELECT * FROM universities WHERE user_author_id=?", current_user)

    return render_template("profil.html", user=user, profil_details=rows, row_count=len(rows)), 201

@app.route("/login", methods=["GET", "POST"])
# @csrf.exempt
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