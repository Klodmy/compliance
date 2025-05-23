from flask import Flask, request, render_template, session, redirect, url_for, flash
import sqlite3
import uuid
from utils import ex_check, send_email, get_submission_status
import os
from random import randint
from dotenv import load_dotenv
import secrets
from datetime import date, timedelta, datetime
from werkzeug.utils import secure_filename

### INITIATON, SETTINGS, CONSTANTS ###

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





### ADMIN REGISTRATION AND LOGIN ###



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
        company_name = request.form.get("company_name")
        login = request.form.get("login")
        password = request.form.get("password")
        password2 = request.form.get("password2")
        email = request.form.get("email")

        # check if all gethered and password confirmed
        if login and password and password2 and email:
            if password == password2:
                
                # create new user in db
                db.execute("INSERT INTO admin_users (login, password, email, name) VALUES (?, ?, ?, ?)", (company_name, login, password, email))
                db.commit()

                # sands back to login
                return redirect("/login")

    # rendering registration page       
    return render_template("registration.html")





### ADMIN CONTROLS - DASHBOARD, ADDING SUBMITTERS, DOCUMENTS, SETS, PROJECTS, REQUESTS ###



#main page
@app.route("/", methods=['GET', 'POST'])
def main():
    return redirect("/login")



# administrator dashboard
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
        request_name = request.form.get("name")
        description = request.form.get("description")
        project = request.form.get("project")
        sub = request.form.get("submitter")
        doc_set = request.form.get("set")
        token = secrets.token_urlsafe(10)

        if project and sub and doc_set:
            
            # assigning this to variable in order to get ID later on
            cur = db.execute("INSERT INTO requests (name, description, project_id, submitter_id, requirement_set_id, admin_id, token) VALUES (?, ?, ?, ?, ?, ?, ?)", (request_name, description, project, sub, doc_set, user_id, token))
            db.commit()

            # gets ID of the last added row
            request_id = cur.lastrowid

            # get data to send email
            user_name = db.execute("SELECT login FROM admin_users WHERE id = ?", (user_id,)).fetchone()
            company_name = db.execute("SELECT name FROM admin_users WHERE id = ?", (user_id,)).fetchone()
            submitter_email = db.execute("SELECT email FROM submitting_users WHERE id = ?", (sub,)).fetchone()
            the_project = db.execute("SELECT project_name FROM project WHERE id = ?", (project,)).fetchone()
            sub_token = db.execute("SELECT token FROM submitting_users WHERE id = ?", (sub,)).fetchone()

            # body of the email in case reveiving browser does not render html
            body = f"You have a submittal request from {user_name['login']}. Please follow the following link to login: http://127.0.0.1:5000/submitter_login"

            # html body of the email
            html_body = (
            f"""
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                        <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                            <h2 style="color: #444;">You have a new submittal request from <span style="color: #007bff;">{company_name}</span></h2>
                            <p>Please log in to your dashboard to review the request.</p>
                            <a href="http://127.0.0.1:5000/submitter_registration/{sub_token}"
                            style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Login to Dashboard</a>
                        </div>
                    </body>
                </html>
                """
            )


            # sends an email
            send_email(submitter_email["email"], f"Submittals request for {the_project['project_name']}", body, html_body, email_password)

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
                            project.id,
                            submitting_users.name, 
                            requests.status,
                            requests.token,
                            requests.name as request_name
                        FROM requests
                        JOIN project ON requests.project_id = project.id
                        JOIN submitting_users ON requests.submitter_id = submitting_users.id
                        WHERE requests.admin_id = ?
                        """, (session.get('id'),)).fetchall()

    return render_template("admin.html", user=user, subs=subs, projects=projects, sets=sets, requests=requests, this_req=this_req)



# submitters management
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



# documents management
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

        # verifies if checkbox of expiry required is checked
        if request.form.get("expiry_required") == "on":
            expiry_required = 1
        else:
            expiry_required = 0

        # insert results into db
        db.execute("INSERT INTO users_docs (name, description, expiry_required, user_id) VALUES (?, ?, ?, ?)", (doc_name, doc_description, expiry_required, user_id))
        db.commit()
        
        # redirects to updated page
        return redirect("/documents_library")

    # get existing docs to display
    docs = db.execute("SELECT id, name, description, expiry_required FROM users_docs WHERE user_id  = ?", (user_id,)).fetchall()

    return render_template("documents_library.html", docs=docs)



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



# individual set eddition
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

        selected = {}

        for doc in all_docs:
            if request.form.get(doc["name"]):

                # checks if added doc is required during submission
                is_required = request.form.get(f"is_required_{doc['name']}") == "on"

                selected[doc["name"]] = int(is_required)
            

        # inserting chosen docs in the set db
        for doc_name, is_required in selected.items():
            db.execute("INSERT INTO requirements (set_id, doc_type, is_required) VALUES (?, ?, ?)", (set_id, doc_name, is_required))
        
        # push collected to db
        db.commit()
        return redirect("/my_sets")
    
    current_set = {}
    
    this_set = db.execute("SELECT doc_type, is_required FROM requirements WHERE set_id = ?", (set_id,)).fetchall()
    for doc in this_set:
        current_set[doc["doc_type"]] = doc["is_required"]

    return render_template("edit.html", current_set=current_set, all_docs=all_docs)



# projects management
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



@app.route("/review_submission/<token>", methods=["GET", "POST"])
def review_submission(token):

    # check for admin 
    if not session.get("admin"):
        return redirect("/login")

    db = get_db()

    # get required submission info
    submission = db.execute("""
        SELECT
            project.project_number,
            project.project_name,
            requests.submitter_id,
            requests.token,
            requests.status,
            requests.requirement_set_id,
            submitting_users.name AS submitter_name,
            docs.*
        FROM requests
        JOIN project ON requests.project_id = project.id
        JOIN submitting_users ON requests.submitter_id = submitting_users.id
        LEFT JOIN docs ON docs.request_id = requests.id
        WHERE requests.token = ?
    """, (token,)).fetchall()

    if not submission:
        flash("Submission not found.")
        return redirect("/admin")

    # get list of required doc types
    requirement_set_id = submission[0]["requirement_set_id"]
    requirements = db.execute(
        "SELECT doc_type FROM requirements WHERE set_id = ?",
        (requirement_set_id,)
    ).fetchall()

    # map submitted docs by doc_type for lookup
    submitted_lookup = {
        doc["doc_type"]: dict(doc) for doc in submission if doc["id"]
    }

    # prepare docs to display (submitted or placeholders)
    docs_to_display = []
    for req in requirements:
        doc_type = req["doc_type"]
        doc = submitted_lookup.get(doc_type)
        if doc:
            docs_to_display.append(doc)
        else:
            docs_to_display.append({
                "doc_type": doc_type,
                "doc_status": "not_submitted",
                "link": None,
                "expiry_date": None,
                "id": None
            })

    # handle form submission
    if request.method == "POST":
        updated_doc_ids = []

        for doc in docs_to_display:
            doc_id = doc.get("id")
            if doc_id:
                new_status = request.form.get(f"status_{doc_id}")
                if new_status:
                    try:
                        db.execute("UPDATE docs SET doc_status = ? WHERE id = ?", (new_status, doc_id))
                        updated_doc_ids.append(doc_id)
                    except Exception as e:
                        print(f"Failed to update doc {doc_id}: {e}")

        db.commit()

        # get request ID for status update
        request_id = db.execute(
            "SELECT id FROM requests WHERE token = ?", (token,)
        ).fetchone()["id"]

        # recalculate overall request status
        docs = db.execute("""
            SELECT
                requirements.doc_type,
                docs.link,
                docs.doc_status,
                requests.status
            FROM requests
            JOIN requirements ON requirements.set_id = requests.requirement_set_id
            LEFT JOIN docs ON docs.request_id = requests.id AND docs.doc_type = requirements.doc_type
            WHERE requests.id = ?
        """, (request_id,)).fetchall()

        new_status = get_submission_status(docs)
        db.execute("UPDATE requests SET status = ? WHERE id = ?", (new_status, request_id))
        db.commit()

        # email the submitter
        request_info = db.execute("SELECT name, submitter_id FROM requests WHERE id = ?", (request_id,)).fetchone()
        submitter_email = db.execute("SELECT email FROM submitting_users WHERE id = ?", (request_info["submitter_id"],)).fetchone()

        subject = f"Status Update: Request {request_info['name']}"
        text_body = f"Your submission {request_info['name']} status was updated to {new_status}."

        html_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                    <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                        <h2>Status Update</h2>
                        <p>The status of your submission <strong>{request_info['name']}</strong> has been updated to <strong>{new_status.replace("_", " ").title()}</strong>.</p>
                        <p>Please log in to your dashboard to view the details.</p>
                        <a href="http://127.0.0.1:5000/submitter_login"
                            style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                            Go to Dashboard
                        </a>
                    </div>
                </body>
            </html>
        """

        send_email(submitter_email["email"], subject, text_body, html_body, email_password)

        flash("Review finalized. Submission status updated and email sent.")
        return redirect(f"/review_submission/{token}")

    return render_template("review_submission.html", docs=docs_to_display, token=token)


# review expiring docs
@app.route("/expiration", methods=['GET', 'POST'])
def expiration():

    # call db
    db = get_db()

    # get current user
    user_id = session.get("id")

    # get current user docs
    docs = db.execute("SELECT * FROM docs WHERE admin_user_id = ?", (user_id,)).fetchall()

    delta = date.today() + timedelta(days=7)

    # list for expiring/ed docs
    expiring = []

    for doc in docs:
        
        # trying to format datestamp to yyyy-mm-dd format
        try:
            expiry = datetime.strptime(doc["expiry_date"], "%Y-%m-%d").date()
            
            # if doc will expire in 7 or less days, or already has been expired
            if expiry <= delta:
                # adding to the list
                expiring.append(doc)

            # skip if not expiring
            else:
                pass
        # print errors
        except Exception as e:         
            print(f"Skipping invalid expiry date: {doc['expiry_date']}")
            
    
    # sorts the list by expiry date, putting closest/oldest first
    expiring.sort(key=lambda doc: datetime.strptime(doc["expiry_date"], "%Y-%m-%d").date())
                
    return render_template("expiration.html", expiring=expiring)







### ADMIN HELPER ROUTES ###



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

# delete docs from library
@app.route("/del_doc/<id>", methods=['POST'])
def del_doc(id):

    db = get_db()

    db.execute("DELETE FROM users_docs WHERE id = ?", (id,))
    db.commit()

    return redirect("/documents_library")


# review all submission of a project
@app.route("/project_summary/<id>")
def project_summary(id):

    db = get_db()

    user = db.execute("SELECT project_admin_id FROM project WHERE id = ?", (id,)).fetchone()

    if not user or session.get("id") != user["project_admin_id"]:
        return redirect("/login")
    
    submissions = db.execute(
        """
    SELECT
    project.project_name,
    project.project_number,
    requests.name,
    requests.token,
    requests.status,
    requests.submitter_id,
    submitting_users.name
    FROM requests
    JOIN project ON project.id = requests.project_id
    JOIN submitting_users ON submitting_users.id = requests.submitter_id
    WHERE project.id = ?
    """, (id)).fetchall()


    return render_template("project_summary.html", submissions=submissions)


### SUBMITTER REGISTRATION AND LOGIN ###



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

        user = db.execute("SELECT * FROM submitting_users WHERE login = ?", (login,)).fetchone()

        if user and password == user["password"]:

            # initiating session
            session["submitter"] = True
            session["id"] = user["id"]

            # redirect to sub dashboard
            return redirect("/submitter_dashboard")
        
        else:
            flash("Login or password is invalid.")
            return redirect("/submitter_login")
        
    return render_template("submitter_login.html")





### SUBMITTER CONTROLS - DASHBOARD, SUBMISSION ###


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
        requests.name as request_name,
        admin_users.name AS gc_name,
        project.project_name
    FROM requests
    JOIN admin_users ON requests.admin_id = admin_users.id
    JOIN project ON requests.project_id = project.id
    WHERE requests.submitter_id = ?
""", (submitter_id,)).fetchall()

    return render_template("submitter_dashboard.html", submitter=submitter, sub_requests=sub_requests)



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
            # gets the file
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

                # gets doc revision
                revision = db.execute("SELECT revision FROM docs WHERE request_id = ? and doc_type = ?", (doc_request['id'], doc_type)).fetchone()
                

                rev = revision["revision"] + 1 if revision else 0

                # cleans up old doc submission in case re-submission is required
                db.execute("DELETE FROM docs WHERE request_id = ? AND doc_type = ?", (doc_request["id"], doc_type))

                # adds information about this submission to db
                db.execute("INSERT INTO docs (submitting_user_id, link, date_submitted, expiry_date, confirmation, doc_type, request_id, admin_user_id, doc_status, filepath, revision) VALUES (?, ?, datetime('now'), ?, 'pending', ?, ?, ?, ?, ?, ?)", (session['id'], filepath, expiry, doc_type, doc_request["id"], doc_request["admin_id"], "pending_review", filepath, rev))
            
        db.commit()

    # get project name to display
    project_name = db.execute("SELECT project_name FROM project WHERE id = ?", (doc_request["project_id"],)).fetchone()

    # get submitted docs for this request
    submitted_docs = db.execute("SELECT * FROM docs WHERE request_id = ?", (doc_request["id"],)).fetchall()

    # turn into dict by doc_type
    submitted_lookup = {doc["doc_type"]: dict(doc) for doc in submitted_docs}

    # merge with required_docs
    docs_to_display = []

    for req in required_docs:
        doc_type = req["doc_type"]
        doc = submitted_lookup.get(doc_type)

        if doc:
            docs_to_display.append(doc)
        else:
            docs_to_display.append({
                "doc_type": doc_type,
                "doc_status": "not_submitted",
                "link": None,
                "expiry_date": None,
                "id": None
            })

        
    return render_template("submission.html", project_name=project_name, doc_request=doc_request, required_docs=docs_to_display)





### SUBMITTER HELPER ROUTES ###



# enables sub to delete file
@app.route("/delete_doc/<doc_id>", methods=['POST'])
def delete_doc(doc_id):

    db = get_db()

    # get's id of the submitter that uploaded the file
    doc = db.execute("SELECT id, submitting_user_id, filepath FROM docs WHERE id = ?", (doc_id,)).fetchone()

    # checks against currect session id and block unauthorized attempts
    if not session.get("id") or session.get("id") != doc["submitting_user_id"]:
        return "Unauthorized", 403
    
    else:
        # get token of the submission of the file that is beigh deleted
        token = db.execute("""
                        SELECT
                            requests.token
                            FROM requests
                            JOIN docs ON docs.request_id = requests.id
                            WHERE docs.id = ?
                            """, (doc_id,)).fetchone()
        

        # adds record of the deleted file to the db
        db.execute("INSERT INTO deleted_docs (original_doc_id, submitter_id, filepath) VALUES (?, ?, ?)", (doc["id"], doc["submitting_user_id"], doc["filepath"]))

        # deletes actual file
        if doc and doc["filepath"]:
            try:
                os.remove(doc["filepath"])
            except Exception as e:
                print(f"Error deleting file: {e}")


        # removes file from docs
        db.execute("DELETE FROM docs WHERE id = ?", (doc_id,))
        db.commit()

        flash("Document deleted successfully.")

        return redirect(f"/submission/{token['token']}")
    









