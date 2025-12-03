from flask import Flask,render_template,render_template_string,send_from_directory,request,redirect,url_for
from os import popen
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import urllib.parse

app=Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'lol_i_am_the_admin'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

jwt=JWTManager(app)

# Command injection filter 
def filter(cmd):
    notAllowed=["flag.txt","cat","head","tail","flag"]
    for c in notAllowed:
        if c in cmd :
            return False
    return True

# Home page
@app.route("/")
def home():
    return send_from_directory("templates", "index.html")

# SSTI challenge
@app.route("/template")
def template():
    name = request.args.get("name")
    if name:
        if '{' in name or '}' in name:
            return render_template_string("Hacker",status_word="Hacker"), 403

    html=f"""
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Hi {name}</h2>
    </body>
    </html>
    """
    return render_template_string(html)

# Command injection challenge
@app.route("/run")
def about():
    cmd = request.args.get('cmd', '')
    
    if not cmd:
        return render_template("run.html")
    cmd = request.args.get('cmd', '')
    
    allowed = filter(cmd)
    if not allowed:
        return render_template("run.html",output="Hacker"), 403
    
    output=popen(f"ping -c 2 {cmd}").read()
    return render_template("run.html",output=f"{output}")

@app.route("/login",methods=["GET", "POST"])
def login():
    if request.method=="GET":
        return render_template("login.html")
    elif request.method=="POST":

        if not username or not password:
            return jsonify({"error": "Email and password required"}), 400

        username = request.form["username"]
        password = request.form["password"]
        if username=="admin" and password=="admin":
            return redirect(url_for("home"))


if __name__=="__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)