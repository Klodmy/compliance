from flask import Flask, request, render_template, session, redirect, url_for, flash
import sqlite3
import uuid
from utils import ex_check
import os


app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "mysecret"
os.environ["FLASK_ENV"] = "development"

# set uploads folder and allowed extensions
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = ["pdf", "png", "jpg", "jpeg"]
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# connects database
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

#main page
@app.route("/", methods=['GET', 'POST'])
def main():
    return redirect("/login")


# handles login
@app.route("/login", methods=['GET', 'POST'])
def login():

    # call db
    db = get_db()

    # allows new user to go and register
    if request.method == "POST":
        if request.form.get("registration"):
            return redirect("/registration")
        
        # getting credentials
        form_login = request.form["login"]
        form_password = request.form["password"]

        # getting user by login
        user = db.execute("SELECT * FROM users WHERE login = ?", (form_login, )).fetchone()

        # checking user's password, redirects to admin panel if ok
        if user and form_password == user["password"]:
            session["admin"] = True
            session["id"] = user["id"]

            return redirect("/admin")

        # if any mistakes
        else:
            return render_template("login.html", error="Login or password is wrong!")
        
    # renders login page
    return render_template("login.html")

@app.route("/registration", methods=['GET', 'POST'])
def registration():

    # call db
    db = get_db()
    
    if request.method == "POST":

        # getting new credentials 
        login = request.form.get("login")
        password = request.form.get("password")
        password2 = request.form.get("password2")
        email = request.form.get("email")
        token = str(uuid.uuid4())

        # check if all gethered and password confirmed
        if login and password and password2 and email:
            if password == password2:
                
                # create new user in db
                db.execute("INSERT INTO users (login, password, token, role, email) VALUES (?, ?, ?, ?, ?)", (login, password, token, "gc", email))
                db.commit()

                # sands back to login
                return redirect("/login")

    # rendering registration page       
    return render_template("registration.html")


@app.route("/admin", methods=['GET', 'POST'])
def admin():

    db = get_db()
    user_id = session.get("id")

    # redirect if not logged in
    if not user_id:
        return redirect("/login")

    
    if request.method == "POST":

        # getting data from the form
        new_login = request.form.get("new_login")
        new_password = request.form.get("new_password")
        new_token = str(uuid.uuid4())
        email = request.form.get("email")
        # dropdown, select from created ones, if none - proposes standard
        requirement_set = request.form.get("requirement_set")

        # adding sub
        db.execute("INSERT INTO users (login, password, token, created_by, email, requirement_set_id, role) VALUES (?, ?, ?, ?, ?, ?, ?)", (new_login, new_password, new_token, user_id, email, requirement_set, "sub"))
        db.commit()

    # creating a user 
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["id"],)).fetchone()
    subs = db.execute("SELECT * FROM users WHERE created_by = ?", (session["id"],)).fetchall()
    req_sets = db.execute("SELECT id, name FROM requirement_sets WHERE gc_id = ?", (user_id,)).fetchall()

    return render_template("admin.html", user=user, subs=subs, req_sets=req_sets)


@app.route("/delete_sub", methods=['POST'])
def delete_user():

    db = get_db()
    token = request.form.get("token")

    if token:
        db.execute("DELETE FROM users WHERE token = ? and role = 'sub'", (token, ))
        db.commit()
        return redirect("/admin")



@app.route("/submission/<token>", methods=['GET', 'POST'])
def submission(token):

    # call db
    db = get_db()

    # get data of the user that is submitting
    submitting_user = db.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()

    # check if data is missing/no user
    if not submitting_user:
        return "Invalid or expired link", 404
    
    # if user submits the form
    if request.method == "POST":
        # get all required docs for this user
        required_docs = db.execute("SELECT doc_type FROM requirements WHERE set_id = ?", (submitting_user["requirement_set_id"],)).fetchall()

        # looping through required docs
        for doc in required_docs:
            # getting doc type
            doc_type = doc["doc_type"]
            # gets the actual file
            file = request.files.get(doc_type)

            # checks if there is file, it has name and extension is allowed
            if file and file.filename and ex_check(file.filename, ALLOWED_EXTENSIONS):
                # assign file name in readable format
                filename = f"{submitting_user['id']}_{doc_type}_{file.filename}"
                # join upload folder and new file name
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                # saves expiry date
                expiry = request.form.get(f"{doc_type}_expiry")
                # saves the file
                file.save(filepath)

                # adds information about this submission to db
                db.execute("INSERT INTO docs (user_id, link, date_submitted, expiry_date, confirmation, doc_type) VALUES (?, ?, datetime('now'), ?, 'pending', ?)", (submitting_user['id'], filepath, expiry, doc_type))
            
        db.commit()
        

    return render_template("submission.html", user=submitting_user)