from flask import Flask, request, render_template, session, redirect, url_for, flash
import sqlite3
import uuid
from utils import ex_check, send_email, get_submission_status
import os
from random import randint
from dotenv import load_dotenv
import secrets
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "mysecret"
os.environ["FLASK_ENV"] = "development"


# set uploads folder and allowed extensions, set email password
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = ["pdf", "png", "jpg", "jpeg"]
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
email_password = os.environ.get("EMAIL_APP_PASSWORD")
load_dotenv()

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





@app.route("/logout")
def logout():

    # clears session, returns to login page based on user's role
    if session.get("admin"):
        session.clear()
        return redirect("/login")
    elif session.get("submitter"):
        session.clear()
        return redirect("/submitter_login")
    else:
        session.clear()
        return redirect("/")




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
    

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    
    if request.method == "POST":

        # request required data from a form
        project = request.form.get("project")
        sub = request.form.get("submitter")
        doc_set = request.form.get("set")
        token = secrets.token_urlsafe(10)

        if project and sub and doc_set:
            
            # assigning this to variable in order to get ID later on
            cur = db.execute("INSERT INTO requests (project_id, submitter_id, requirement_set_id, admin_id, token) VALUES (?, ?, ?, ?, ?)", (project, sub, doc_set, user_id, token))
            db.commit()

            # gets ID of the last added row
            request_id = cur.lastrowid

            # get data to send email
            user_name = db.execute("SELECT login FROM admin_users WHERE id = ?", (user_id,)).fetchone()
            submitter_email = db.execute("SELECT email FROM submitting_users WHERE id = ?", (sub,)).fetchone()
            the_project = db.execute("SELECT project_name FROM project WHERE id = ?", (project,)).fetchone()
            sub_token = db.execute("SELECT token FROM submitting_users WHERE id = ?", (sub,)).fetchone()

            # body of the emai in case reveiving app does not render html
            body = f"You have a submittal request from {user_name['login']}. Please follow the following link to login: http://127.0.0.1:5000/submitter_login"

            # sends an email
            send_email(user_name["login"], submitter_email["email"], f"Submittals request for {the_project['project_name']}", body, email_password, sub_token['token'])

            return redirect("/admin")
    
   # getting admin, submitters, projects
    user = db.execute("SELECT * FROM admin_users WHERE id = ?", (session["id"],)).fetchone()
    subs = db.execute("SELECT * FROM submitting_users WHERE invited_by = ?", (session["id"],)).fetchall()
    projects = db.execute("SELECT * FROM project WHERE project_admin_id = ?", (user_id,)).fetchall()
    sets = db.execute("SELECT * FROM requirement_sets WHERE admin_user_id = ?", (user_id,)).fetchall()
    requests = db.execute("SELECT * FROM requests").fetchall()

    this_req = db.execute("""
                        SELECT 
                            project.project_number, 
                            project.project_name, 
                            submitting_users.name, 
                            requests.status,
                            requests.token
                        FROM requests
                        JOIN project ON requests.project_id = project.id
                        JOIN submitting_users ON requests.submitter_id = submitting_users.id
                        WHERE requests.admin_id = ?
                        """, (session.get('id'),)).fetchall()

    return render_template("admin.html", user=user, subs=subs, projects=projects, sets=sets, requests=requests, this_req=this_req)




# removes sub from the db when "delete" button is hit
@app.route("/delete_sub", methods=['POST'])
def delete_sub():
    # call db
    db = get_db()
    # gets user's token
    token = request.form.get("token")
    sub = db.execute("SELECT name FROM submitting_users WHERE token = ?", (token,)).fetchone()
    

    # if got, deletes this user from the db
    if token:
        flash(f"Submitter {sub['name']} has been successfully deleted.")
        db.execute("DELETE FROM submitting_users WHERE token = ?", (token,))
        db.commit()
        
    return redirect("/my_submitters")




# page for the submission of the documents by the request
@app.route("/submission/<token>", methods=['GET', 'POST'])
def submission(token):

    # call db
    db = get_db()

    # get data of the request
    doc_request = db.execute("SELECT * FROM requests WHERE token = ?", (token,)).fetchone()

    # check in case token is not valid
    if not doc_request:
        return "Invalid token", 404
    
     # get all required docs for this user
    required_docs = db.execute("SELECT doc_type FROM requirements WHERE set_id = ?", (doc_request["requirement_set_id"],)).fetchall()
    
    # if user submits the form
    if request.method == "POST":
       

        # looping through required docs
        for doc in required_docs:
            # getting doc type
            doc_type = doc["doc_type"]
            # gets the actual file
            file = request.files.get(doc_type)

            # checks if there is file, it has name and extension is allowed
            if file and file.filename and ex_check(file.filename, ALLOWED_EXTENSIONS):
                # assign file name in readable format
                filename = f"{session['id']}_{doc_type}_{file.filename}"
                # join upload folder and new file name
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                # saves expiry date
                expiry = request.form.get(f"{doc_type}_expiry")
                # saves the file
                file.save(filepath)

                # adds information about this submission to db
                db.execute("INSERT INTO docs (submitting_user_id, link, date_submitted, expiry_date, confirmation, doc_type, request_id, admin_user_id) VALUES (?, ?, datetime('now'), ?, 'pending', ?, ?, ?)", (session['id'], filepath, expiry, doc_type, doc_request["id"], doc_request["admin_id"]))
            
        db.commit()
        
    return render_template("submission.html", doc_request=doc_request, required_docs=required_docs)




# sets management
@app.route("/my_sets", methods=['GET', 'POST'])
def my_sets():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    db = get_db()

    # gets current user id
    user_id = session["id"]

    if request.method == "POST":

        requirement_set = request.form.get("new_set_name")

        db.execute("INSERT INTO requirement_sets (admin_user_id, name) VALUES (?, ?)", (user_id, requirement_set))
        db.commit()

    
    # gets all doc sets this user has
    doc_sets = db.execute("SELECT id, name FROM requirement_sets WHERE admin_user_id = ?", (user_id, )).fetchall()

    # loops through requirement sets and gets docs in them and adds to the dict
    docs_by_set = {}

    for doc_set in doc_sets:
        set_id = doc_set["id"]
        docs = db.execute("SELECT doc_type FROM requirements WHERE set_id = ?", (set_id,)).fetchall()
        docs_by_set[set_id] = docs

    return render_template("my_sets.html", doc_sets=doc_sets, docs_by_set=docs_by_set)




@app.route("/my_sets/<set_id>", methods=['GET', 'POST'])
def edit_set(set_id):

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    db = get_db()
    user_id = session.get("id")

    # get docs created by user
    all_docs = db.execute("SELECT * FROM users_docs WHERE user_id = ?", (user_id,)).fetchall()

    if request.method == "POST":

        # deletes previous required docs if any
        db.execute("DELETE FROM requirements WHERE set_id = ?", (set_id,))

        selected = []
        
        # looping through all possible docs, if it is selected adds it to this set
        for doc in all_docs:
            if request.form.get(doc["name"]):
                selected.append(doc["name"])

        # inserting chosen docs in the set db
        for selected_doc in selected:
            db.execute("INSERT INTO requirements (set_id, doc_type) VALUES (?, ?)", (set_id, selected_doc))
        
        # push collected to db
        db.commit()
        return redirect("/my_sets")
    
    
    current_set = []
    
    this_set = db.execute("SELECT doc_type FROM requirements WHERE set_id = ?", (set_id,)).fetchall()
    for doc in this_set:
        current_set.append(doc["doc_type"])

    

    return render_template("edit.html", current_set=current_set, all_docs=all_docs)




@app.route("/documents_library", methods=['GET', 'POST'])
def documents_library():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

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

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")
    
    # call db, get user id
    db = get_db()
    user_id = session.get("id")

    if request.method == "POST":
        
        # get project number and name through the form
        project_number = request.form.get("project_number")
        project_name = request.form.get("project_name")

        # add to the db
        db.execute("INSERT INTO project (project_number, project_name, project_admin_id) VALUES (?, ?, ?)", (project_number, project_name, user_id))
        db.commit()

        # refresh page
        return redirect("/projects")
    
    # get existing projects
    projects = db.execute("SELECT project_number, project_name FROM project WHERE project_admin_id = ?", (user_id,)).fetchall()
    
    return render_template("projects.html", projects=projects)




@app.route("/my_submitters", methods=['GET', 'POST'])
def my_submitters():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

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
        flash(f"Submitter {name} was successfully added.")
        return redirect("/my_submitters")
    
    # get existing submitters
    submitters = db.execute("SELECT name, email, token FROM submitting_users WHERE invited_by = ?", (user_id,)).fetchall()

    return render_template("my_submitters.html", submitters=submitters)





@app.route("/submitter_registration/<token>", methods=["GET", "POST"])
def submitter_registration(token):

    db = get_db()
    submitter = db.execute("SELECT * FROM submitting_users WHERE token = ?", (token,)).fetchone()

    if request.method == "POST":

        # getting new credentials 
        login = request.form.get("login")
        password = request.form.get("password")
        password2 = request.form.get("password2")

        if login and password and password2 and submitter:
            if password == password2:
                
            # create new user in db
                db.execute("UPDATE submitting_users SET login = ?, password = ? WHERE token = ?", (login, password, token))
                db.commit()

                # sands back to login
                return redirect("/submitter_login")

    # rendering registration page       
    return render_template("submitter_registration.html")






@app.route("/submitter_login", methods=["GET", "POST"])
def submitter_login():

    # calls db
    db = get_db()

    if request.method == "POST":
        
        # request information through forms
        login = request.form.get("login")
        password = request.form.get("password")

        print("Submitted login:", login)
        print("Submitted password:", password)

        user = db.execute("SELECT * FROM submitting_users WHERE login = ?", (login,)).fetchone()

        print(user["login"])
        print(user["password"])

        if user and password == user["password"]:

            # initiating session
            session["submitter"] = True
            session["id"] = user["id"]

            # redirect to sub dashboard
            return redirect("/submitter_dashboard")
        
    return render_template("submitter_login.html")
        


@app.route("/submitter_dashboard", methods=['GET', 'POST'])
def submitter_dashboard():

    # redirect if not logged in as admin
    if not session.get("submitter"):
        return redirect("/login")

    # db call, gets admin's id
    db = get_db()
    submitter_id = session.get("id")
    

    # redirect if not logged in
    if not submitter_id and not session.get("submitter"):
        return redirect("/submitter_login")

    # get submitter
    submitter = db.execute("SELECT * FROM submitting_users WHERE id = ?", (submitter_id,)).fetchone()

    # get information about request to display
    sub_requests = db.execute("""
    SELECT 
        requests.project_id,
        requests.admin_id,
        requests.token,
        requests.status,
        admin_users.login AS gc_name,
        project.project_name
    FROM requests
    JOIN admin_users ON requests.admin_id = admin_users.id
    JOIN project ON requests.project_id = project.id
    WHERE requests.submitter_id = ?
""", (submitter_id,)).fetchall()

    return render_template("submitter_dashboard.html", submitter=submitter, sub_requests=sub_requests)


@app.route("/review_submission/<token>")
def review_submission(token):

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    db = get_db()

    # get information about submission to show admin for review
    submission = db.execute("""
    SELECT
        project.project_number,
        project.project_name,
        requests.submitter_id,
        requests.token,
        requests.status,
        submitting_users.name,
        docs.*
    FROM requests
    JOIN project ON requests.project_id = project.id
    JOIN submitting_users ON requests.submitter_id = submitting_users.id
    JOIN docs ON docs.request_id = requests.id
    WHERE requests.token = ?""", (token,)).fetchall()

    return render_template("review_submission.html", submission=submission)



@app.route("/change_status", methods=['POST'])
def change_status():

    db = get_db()

    # get updated status and document id
    new_status = request.form.get("new_status")
    doc_id = request.form.get("doc_id")


    token = db.execute("""
    SELECT
        requests.token,
        requests.id
    FROM requests
    JOIN docs ON docs.request_id = requests.id
    WHERE docs.id = ?    
    """, (doc_id,)).fetchone()

    # if provided update db
    if new_status and doc_id:

        db.execute("UPDATE docs SET doc_status = ? WHERE id = ?", (new_status, doc_id))
        db.commit()

        # gets docs from this request and checks for the whole submission status
        docs = db.execute("SELECT * FROM docs WHERE request_id = ?", (token['id'],)).fetchall()
        new_request_status = get_submission_status(docs)

        # updates submission status
        db.execute("UPDATE requests SET status = ? WHERE id = ?", (new_request_status, token['id']))
        db.commit()

    flash("Status updated successfully.")
    return redirect(f"/review_submission/{token['token']}")