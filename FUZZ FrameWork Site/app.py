from flask import Flask,render_template,render_template_string,send_from_directory,request
from os import popen
import urllib.parse
app=Flask(__name__)

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
    html=f"""
    <!DOCTYPE html>
    <html>
    <body>
        <h2>Hi {name}</h2>
    </body>
    </html>
    """
    return render_template_string(html,name=name)

# Command injection challenge
@app.route("/run")
def about():
    cmd = request.args.get('cmd', '')
    
    if not cmd:
        return render_template("run.html")
    cmd = request.args.get('cmd', '')
    
    allowed = filter(cmd)
    if not allowed:
        return render_template("run.html",output="Hacker")
    
    output=popen(f"ping -c 2 {cmd}").read()
    return render_template("run.html",output=f"{output}")

if __name__=="__main__":
    app.run(debug=True,host='0.0.0.0', port=5000)