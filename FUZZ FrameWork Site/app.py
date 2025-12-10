from flask import Flask, render_template, render_template_string, send_from_directory, request, redirect, url_for, jsonify, make_response
import os
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from urllib.parse import unquote

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'lol_i_am_the_admin'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=8)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_CSRF_PROTECT'] = False  

jwt = JWTManager(app)

# Command injection filter 
def filter(cmd):
    notAllowed = ["head", "cat", "tail", "etc","(",";",")","&","|"]
    for c in notAllowed:
        if c in cmd:
            return False
    return True

# Home page
@app.route("/")
@jwt_required()
def home():
    current_user = get_jwt_identity()
    return render_template("index.html")

# LFI challenge
@app.route("/read",methods=["GET","POST"])
@jwt_required()
def template():
    if request.method=="GET":
        return render_template("read.html")
    elif request.method=="POST":
        path = request.form.get("filename","")
        if "/" in path: return "LOL try harder"
        path=unquote(path)
        if "../" in path:
            path=path.replace("../","")
        path=os.path.normpath(path)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as file:
                content = file.read()
        except Exception as e:
            content = f"Error: {e}"

        return render_template("view.html", content=content)

    

# Command injection 
@app.route("/run", methods=["GET","POST"])
@jwt_required()
def run():
    current_user = get_jwt_identity()
    cmd = request.form.get('cmd', '')
    
    if not cmd:
        return render_template("run.html", user=current_user)
    
    allowed = filter(cmd)
    if not allowed:
        return render_template("run.html", output="Hacker", user=current_user), 403
    
    output = os.popen(f"ping -c 2 {cmd}").read()
    return render_template("run.html", output=f"{output}", user=current_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400

        if username == "admin" and password == "monkey":
            # Create JWT token with username and password
            access_token = create_access_token(
                identity=username
            )
            
            # Create response and set JWT token in cookie
            response = make_response(redirect(url_for("home")))
            response.set_cookie('access_token_cookie', access_token, httponly=True, max_age=3600)
            
            return response
        else:
            return render_template("login.html", error="Invalid credentials"), 401

@app.route("/logout", methods=["POST"])
def logout():
    response = make_response(redirect(url_for("login")))
    response.set_cookie('access_token_cookie', '', expires=0)
    return response


@jwt.unauthorized_loader
def unauthorized_callback(callback):
    return "Forbidden",403

# Admin
@app.route("/admin")
@jwt_required()
def admin():
    return os.getenv("FLAG1")

@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)