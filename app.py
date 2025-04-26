from flask import Flask, request, render_template, session, redirect, url_for, flash
import sqlite3
import uuid
from utils import ex_check
import os
from random import randint


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
        user = db.execute("SELECT * FROM admin_users WHERE login = ?", (form_login, )).fetchone()

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



# registration
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
        name = request.form.get("name")
        token = str(uuid.uuid4())

        # check if all gethered and password confirmed
        if login and password and password2 and email:
            if password == password2:
                
                # create new user in db
                db.execute("INSERT INTO admin_users (login, password, email, name) VALUES (?, ?, ?, ?)", (login, password, email, name))
                db.commit()

                # sands back to login
                return redirect("/login")

    # rendering registration page       
    return render_template("registration.html")




# main operational page for gc
@app.route("/admin", methods=['GET', 'POST'])
def admin():

    # db call, gets admin's id
    db = get_db()
    user_id = session.get("id")

    # redirect if not logged in
    if not user_id:
        return redirect("/login")

    
    #if request.method == "POST":
    


    # getting admin, submitters, projects
    user = db.execute("SELECT * FROM admin_users WHERE id = ?", (session["id"],)).fetchone()
    subs = db.execute("SELECT * FROM submitting_users WHERE invited_by = ?", (session["id"],)).fetchall()
    projects = db.execute("SELECT * FROM project WHERE project_admin_id = ?", (user_id,)).fetchall()

    return render_template("admin.html", user=user, subs=subs, projects=projects)




# removes sub from the db when "delete" button is hit
@app.route("/delete_sub", methods=['POST'])
def delete_user():
    # call db
    db = get_db()
    # gets user's token
    token = request.form.get("token")

    # if got, deletes this user from the db
    if token:
        db.execute("DELETE FROM users WHERE token = ? and role = 'sub'", (token, ))
        db.commit()
        return redirect("/admin")




# page for the submission of the documents by the sub
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




# sets management
@app.route("/my_sets", methods=['GET', 'POST'])
def my_sets():

    db = get_db()

    # gets current user id
    user_id = session["id"]

    if request.method == "POST":

        requirement_set = request.form.get("new_set_name")

        db.execute("INSERT INTO requirement_sets (gc_id, name) VALUES (?, ?)", (user_id, requirement_set))
        db.commit()

    
    # gets all doc sets this user has
    doc_sets = db.execute("SELECT id, name FROM requirement_sets WHERE gc_id = ?", (user_id, )).fetchall()

    # loops through requirement sets and gets docs in them and adds to the dict
    docs_by_set = {}

    for doc_set in doc_sets:
        set_id = doc_set["id"]
        docs = db.execute("SELECT doc_type FROM requirements WHERE set_id = ?", (set_id,)).fetchall()
        docs_by_set[set_id] = docs

    return render_template("my_sets.html", doc_sets=doc_sets, docs_by_set=docs_by_set)




@app.route("/my_sets/<set_id>", methods=['GET', 'POST'])
def edit_set(set_id):

    db = get_db()
    current_set = [doc["doc_type"] for doc in db.execute("SELECT doc_type FROM requirements WHERE set_id = ?", (set_id,)).fetchall()]
    # list of allowed docs
    all_docs = ["WSIB", "COI", "Training", "Form 1000", "Other"]

    if request.method == "POST":

        # deletes previous required docs if any
        db.execute("DELETE FROM requirements WHERE set_id = ?", (set_id,))

        selected = []
        
        # looping through all possible docs, if it is selected adds it to this set
        for doc in all_docs:
            if request.form.get(doc):
                selected.append(doc)

        # inserting chosen docs in the set db
        for selected_doc in selected:
            db.execute("INSERT INTO requirements (set_id, doc_type) VALUES (?, ?)", (set_id, selected_doc))
        
        # push collected to db
        db.commit()
        return redirect("/my_sets")

    return render_template("edit.html", current_set=current_set)




@app.route("/documents_library", methods=['GET', 'POST'])
def documents_library():

    # call db, get user id
    db = get_db()
    user_id = session.get("id")

    if request.method == "POST":

        # get doc name and description
        doc_name = request.form.get("doc_name")
        doc_description = request.form.get("doc_description")

        # insert results into db
        db.execute("INSERT INTO users_docs (name, description, user_id) VALUES (?, ?, ?)", (doc_name, doc_description, user_id))
        db.commit()
        
        # redirects to updated page
        return redirect("/documents_library")

    # get existing docs to display
    docs = db.execute("SELECT name, description FROM users_docs WHERE user_id  = ?", (user_id,)).fetchall()
    return render_template("documents_library.html", docs=docs)



@app.route("/projects", methods=['GET', 'POST'])
def projects():
    
    # call db, get user id
    db = get_db()
    user_id = session.get("id")

    if request.method == "POST":
        
        # get project number and name through the form
        project_number = request.form.get("project_number")
        project_name = request.form.get("project_name")

        # add to the db
        db.execute("INSERT INTO projects (project_number, project_name, project_admin_id) VALUES (?, ?, ?)", (project_number, project_name, user_id))
        db.commit()

        # refresh page
        return redirect("/projects")
    
    # get existing projects
    projects = db.execute("SELECT project_number, project_name FROM project WHERE project_admin_id = ?", (user_id,)).fetchall()
    
    return render_template("projects.html", projects=projects)

@app.route("/add_submitter", methods=['GET', 'POST'])
def add_submitter():

    db = get_db()
    user_id = session.get("id")

    if request.method == "POST":

        # creating token and requesting new invited user's email
        new_token = str(uuid.uuid4())
        name = request.form.get("name")
        email = request.form.get("email")


        # adding new user dummy data
        db.execute("INSERT INTO submitting_users (login, password, email, token, invited_by, name) VALUES (?, ?, ?, ?, ?, ?)", (str(randint(1, 1000)), str(randint(1, 1000)), email, new_token, user_id, name))
        db.commit()
        return redirect("/add_submitter")
    
    # get existing submitters
    submitters = db.execute("SELECT name, email FROM submitting_users WHERE invited_by = ?", (user_id,)).fetchall()

    return render_template("add_submitter.html", submitters=submitters)