from flask import Flask, request, render_template, session, redirect, flash, g, abort, send_file
import boto3
import uuid
from utils import ex_check, send_email, get_submission_status, upload_file_to_s3, generate_presigned_url
import os
from random import randint
from dotenv import load_dotenv
import secrets
from datetime import date, timedelta, datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import psycopg2.extras
from flask_wtf.csrf import CSRFProtect
import io
import zipfile
import json


### INITIATON, SETTINGS, CONSTANTS ###

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.secret_key = "mysecret"
os.environ["FLASK_ENV"] = "development"
csfr = CSRFProtect()
csfr.init_app(app)


# set uploads folder and allowed extensions, set email password
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = ["pdf", "png", "jpg", "jpeg"] 
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
email_password = os.environ.get("EMAIL_APP_PASSWORD")
load_dotenv()

# connects database
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(
            os.getenv("DATABASE_URL"),
            cursor_factory=psycopg2.extras.RealDictCursor
        )
    return g.db

def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()





### ADMIN REGISTRATION AND LOGIN ###



# handles login
@app.route("/login", methods=['GET', 'POST'])
def login():

    # call db
    db = get_db().cursor()

    # allows new user to go and register
    if request.method == "POST":
        if request.form.get("registration"):
            return redirect("/registration")
        
        # getting credentials
        form_login = request.form["login"]
        form_password = request.form["password"]

        # getting user by login
        db.execute("SELECT * FROM admin_users WHERE login = %s", (form_login, ))
        user = db.fetchone()
        # checking user's password, redirects to admin panel if ok
        if user and check_password_hash(user["password"], form_password):
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
    con = get_db()
    db = get_db().cursor()
    
    if request.method == "POST":

        # getting new credentials 
        # getting new credentials 
        login = request.form.get("login")
        password = request.form.get("password")
        password2 = request.form.get("password2")
        company_name = request.form.get("company_name")
        description = request.form.get("description")
        email = request.form.get("email")
        phone = request.form.get("phone")
        address = request.form.get("address")
        token = secrets.token_urlsafe(10)

        db.execute("SELECT * FROM admin_users WHERE login = %s OR email = %s", (login, email))
        existing = db.fetchone()

        if existing:
            if existing["login"] == login:
                flash("This username is already taken.")
            if existing["email"] == email:
                flash("This email is already in use.")
            return redirect("/registration")
        
        if not request.form.get("agree"):
            return "You must agree to the Privacy Policy and Terms of Service.", 400
        

        # check if all gethered and password confirmed
        if login and password and password2 and email:
            if password == password2:

                # generate hash
                
                hashed_password = generate_password_hash(password)
                
                # create new user in db
                db.execute("INSERT INTO admin_users (login, password, name, description, email, phone, address, token) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (login, hashed_password, company_name, description, email, phone, address, token))
                db.execute("INSERT INTO submitting_users (login, password, name, description, email, phone, address, token) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (login, hashed_password, company_name, description, email, phone, address, token))
                con.commit()

                # sands back to login
                return redirect("/login")

    # rendering registration page       
    return render_template("registration.html")





### ADMIN CONTROLS - DASHBOARD, ADDING SUBMITTERS, DOCUMENTS, SETS, PROJECTS, REQUESTS ###



#main page
@app.route("/", methods=['GET', 'POST'])
def main():
    return render_template("landing.html")



# administrator dashboard
@app.route("/admin", methods=['GET', 'POST'])
def admin():

    # db call, gets admin's id
    con = get_db()
    db = get_db().cursor()
    user_id = session.get("id")
    

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    
    if request.method == "POST":


        if request.form.get("delete"):
            db.execute("DELETE FROM requests WHERE id = %s", (request.form.get("delete"),))
            con.commit()
            flash("Request deleted.")
            return redirect("/admin")
        
        else:
            # request required data from a form
            request_name = request.form.get("name")
            description = request.form.get("description")
            project = request.form.get("project")
            sub = request.form.get("submitter")
            doc_set = request.form.get("set")
            token = secrets.token_urlsafe(10)

            if project and sub and doc_set:
                
                # assigning this to variable in order to get ID later on
                db.execute("INSERT INTO requests (name, description, project_id, submitter_id, requirement_set_id, admin_id, token) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id", (request_name, description, project, sub, doc_set, user_id, token))
                con.commit()

                # gets ID of the last added row
                request_id = db.fetchone()["id"]

                # get data to send email
                db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
                user_name = db.fetchone()

                db.execute("SELECT name FROM admin_users WHERE id = %s", (user_id,))
                company_name = db.fetchone()

                db.execute("SELECT email FROM submitting_users WHERE id = %s", (sub,))
                submitter_email = db.fetchone()

                db.execute("SELECT project_name FROM project WHERE id = %s", (project,))
                the_project = db.fetchone()

                db.execute("SELECT token FROM submitting_users WHERE id = %s", (sub,))
                sub_token = db.fetchone()


                # body of the email in case reveiving browser does not render html
                body = f"You have a submittal request from {user_name['login']}. Please follow the following link to login: http://127.0.0.1:5000/submitter_login"

                # html body of the email
                html_body = (
                f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                            <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                                <h2 style="color: #444;">You have a new submittal request from <span style="color: #007bff;">{company_name['name']}</span></h2>
                                <p>Please log in to your dashboard to review the request.</p>
                                <a href="http://127.0.0.1:5000/submitter_registration/{sub_token['token']}"
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

    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    db.execute("SELECT * FROM admin_users WHERE id = %s", (session["id"],))
    user = db.fetchone()

    db.execute("""SELECT submitting_users.*,
                    admin_submitters.submitter_id
                    FROM submitting_users
                    JOIN admin_submitters
                    ON admin_submitters.submitter_id = submitting_users.id
                    WHERE admin_submitters.admin_id = %s""", (session["id"],))
    subs = db.fetchall()

    db.execute("SELECT * FROM project WHERE project_admin_id = %s", (user_id,))
    projects = db.fetchall()

    db.execute("SELECT * FROM requirement_sets WHERE admin_user_id = %s", (user_id,))
    sets = db.fetchall()

    db.execute("SELECT * FROM requests")
    requests = db.fetchall()

    db.execute("""
                        SELECT 
                            project.project_number, 
                            project.project_name, 
                            project.id as project_id,
                            submitting_users.name,
                            requests.id as req_id,
                            requests.status,
                            requests.token,
                            requests.name as request_name
                        FROM requests
                        JOIN project ON requests.project_id = project.id
                        JOIN submitting_users ON requests.submitter_id = submitting_users.id
                        WHERE requests.admin_id = %s
                        """, (session.get('id'),))
    
    this_req = db.fetchall()

    return render_template("admin.html", user_name=user_name, user=user, subs=subs, projects=projects, sets=sets, requests=requests, this_req=this_req)



# submitters management
@app.route("/my_submitters", methods=['GET', 'POST'])
def my_submitters():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    con = get_db()
    db = get_db().cursor()

    user_id = session.get("id")
    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    if request.method == "POST":

        # creating token and requesting new invited user's email
        new_token = str(uuid.uuid4())
        name = request.form.get("name")
        email = request.form.get("email")

        # check if user with email exists
        db.execute("SELECT * FROM submitting_users WHERE email = %s", (email.strip().lower(),))
        existing_subs = db.fetchone()

        if existing_subs:
            # check if already linked to admin
            db.execute("SELECT * FROM admin_submitters WHERE admin_id = %s AND submitter_id = %s", (user_id, existing_subs["id"]))
            already_taken = db.fetchone()

            # links if not
            if not already_taken:
                db.execute("INSERT INTO admin_submitters (admin_id, submitter_id) VALUES (%s, %s)", (user_id, existing_subs["id"]))
            # passes if it is
            else:
                pass
        else:
            # adding new user dummy data
            db.execute("INSERT INTO submitting_users (login, password, email, token, name) VALUES (%s, %s, %s, %s, %s) RETURNING id", (str(randint(1, 1000)), str(randint(1, 1000)), email.strip().lower(), new_token, name))
            sub_id = db.fetchone()["id"]
            db.execute("INSERT INTO admin_users (login, password, email, token, name) VALUES (%s, %s, %s, %s, %s)", (str(randint(1, 1000)), str(randint(1, 1000)), email.strip().lower(), new_token, name))
            

            db.execute("INSERT INTO admin_submitters (admin_id, submitter_id) VALUES (%s, %s)", (user_id, sub_id))
            

        con.commit()  
        flash(f"Submitter {name} was successfully added.")
        return redirect("/my_submitters")
    
    # get existing submitters
    db.execute("""
                            SELECT 
                            submitting_users.name, 
                            submitting_users.email, 
                            submitting_users.token,
                            admin_submitters.submitter_id
                            FROM submitting_users
                            JOIN admin_submitters ON submitting_users.id = admin_submitters.submitter_id
                            WHERE admin_submitters.admin_id  = %s
""", (user_id,))
    submitters = db.fetchall()

    
    return render_template("my_submitters.html", submitters=submitters, user_name=user_name)



# documents management
@app.route("/documents_library", methods=['GET', 'POST'])
def documents_library():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    # call db, get user id
    con = get_db()
    db = get_db().cursor()
    user_id = session.get("id")
    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    if request.method == "POST":

        # get doc name and description
        doc_name = request.form.get("doc_name")
        doc_description = request.form.get("doc_description")

        # verifies if checkbox of expiry required is checked
        if request.form.get("expiry_required") == "on":
            expiry_required = True
        else:
            expiry_required = False

        # insert results into db
        db.execute("INSERT INTO users_docs (name, description, expiry_required, user_id) VALUES (%s, %s, %s, %s)", (doc_name, doc_description, expiry_required, user_id))
        con.commit()

        flash("Document was successfully added.")
        
        # redirects to updated page
        return redirect("/documents_library")

    # get existing docs to display
    db.execute("SELECT id, name, description, expiry_required FROM users_docs WHERE user_id  = %s", (user_id,))
    docs = db.fetchall()

    return render_template("documents_library.html", docs=docs, user_name=user_name)



# sets management
@app.route("/my_sets", methods=['GET', 'POST'])
def my_sets():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    con = get_db()
    db = get_db().cursor()

    # gets current user id
    user_id = session["id"]
    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    if request.method == "POST":

        requirement_set = request.form.get("new_set_name")

        db.execute("INSERT INTO requirement_sets (admin_user_id, name) VALUES (%s, %s)", (user_id, requirement_set))
        con.commit()

        flash("Set was created successfully.")
    
    # gets all doc sets this user has
    db.execute("SELECT id, name FROM requirement_sets WHERE admin_user_id = %s", (user_id, ))
    doc_sets = db.fetchall()

    # loops through requirement sets and gets docs in them and adds to the dict
    docs_by_set = {}

    for doc_set in doc_sets:
        set_id = doc_set["id"]
        db.execute("SELECT doc_type FROM requirements WHERE set_id = %s", (set_id,))
        docs = db.fetchall()
        docs_by_set[set_id] = docs

    return render_template("my_sets.html", doc_sets=doc_sets, docs_by_set=docs_by_set, user_name=user_name)



# individual set eddition
@app.route("/my_sets/<set_id>", methods=['GET', 'POST'])
def edit_set(set_id):

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")

    con = get_db()
    db = get_db().cursor()
    user_id = session.get("id")
    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    # get docs created by user
    db.execute("SELECT * FROM users_docs WHERE user_id = %s", (user_id,))
    all_docs = db.fetchall()

    if request.method == "POST":

        # deletes previous required docs if any
        db.execute("DELETE FROM requirements WHERE set_id = %s", (set_id,))

        selected = {}

        for doc in all_docs:
            if request.form.get(doc["name"]):

                # checks if added doc is required during submission
                is_required = request.form.get(f"is_required_{doc['name']}") == "on"

                selected[doc["name"]] = is_required
            

        # inserting chosen docs in the set db
        for doc_name, is_required in selected.items():

            # check if expiration is required
            db.execute("SELECT expiry_required FROM users_docs WHERE name = %s AND user_id = %s", (doc_name, user_id))
            ex_req = db.fetchone()

            db.execute("INSERT INTO requirements (set_id, doc_type, is_required, expiry_required) VALUES (%s, %s, %s, %s)", (set_id, doc_name, is_required, ex_req['expiry_required']))
        
        # push collected to db
        con.commit()

        flash("Set was updated successfully.")

        return redirect("/my_sets")
    
    current_set = {}
    
    db.execute("SELECT doc_type, is_required FROM requirements WHERE set_id = %s", (set_id,))
    this_set = db.fetchall()
    for doc in this_set:
        current_set[doc["doc_type"]] = doc["is_required"]

    return render_template("edit.html", current_set=current_set, all_docs=all_docs, user_name=user_name)



# projects management
@app.route("/projects", methods=['GET', 'POST'])
def projects():

    # redirect if not logged in as admin
    if not session.get("admin"):
        return redirect("/login")
    
    # call db, get user id
    con = get_db()
    db = get_db().cursor()
    user_id = session.get("id")

    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    if request.method == "POST":
        
        # get project number and name through the form
        project_number = request.form.get("project_number")
        project_name = request.form.get("project_name")

        # add to the db
        db.execute("INSERT INTO project (project_number, project_name, project_admin_id) VALUES (%s, %s, %s)", (project_number, project_name, user_id))
        con.commit()

        flash("Project was created successfully.")

        # refresh page
        return redirect("/projects")
    
    # get existing projects
    db.execute("SELECT project_number, project_name FROM project WHERE project_admin_id = %s", (user_id,))
    projects = db.fetchall()
    
    return render_template("projects.html", projects=projects, user_name=user_name)



@app.route("/review_submission/<token>", methods=["GET", "POST"])
def review_submission(token):

    # check for admin 
    if not session.get("admin"):
        return redirect("/login")

    con = get_db()
    db = get_db().cursor()
    user_id = session.get("id")
    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    # get required submission info
    db.execute("""
        SELECT
            project.project_number,
            project.project_name,
            requests.submitter_id,
            requests.token,
            requests.id AS request_id,
            requests.status,
            requests.requirement_set_id,
            submitting_users.name AS submitter_name,
            docs.*
        FROM requests
        JOIN project ON requests.project_id = project.id
        JOIN submitting_users ON requests.submitter_id = submitting_users.id
        LEFT JOIN docs ON docs.request_id = requests.id
        WHERE requests.token = %s
    """, (token,))

    submission = db.fetchall()

    req_data = submission[0]

    if not submission:
        flash("Submission not found.")
        return redirect("/admin")

    # get list of required doc types
    requirement_set_id = submission[0]["requirement_set_id"]
    db.execute("SELECT doc_type FROM requirements WHERE set_id = %s",(requirement_set_id,))
    requirements = db.fetchall()

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
                new_comment = request.form.get(f"comment_{doc_id}")
                if new_status:
                    try:
                        db.execute("UPDATE docs SET doc_status = %s, comment = %s WHERE id = %s", (new_status, new_comment, doc_id))
                        updated_doc_ids.append(doc_id)
                    except Exception as e:
                        print(f"Failed to update doc {doc_id}: {e}")

        con.commit()

        # get request ID for status update
        db.execute("SELECT id FROM requests WHERE token = %s", (token,))
        request_id = db.fetchone()["id"]

        # recalculate overall request status
        db.execute("""
            SELECT
                requirements.doc_type,
                docs.link,
                docs.doc_status,
                requests.status
            FROM requests
            JOIN requirements ON requirements.set_id = requests.requirement_set_id
            LEFT JOIN docs ON docs.request_id = requests.id AND docs.doc_type = requirements.doc_type
            WHERE requests.id = %s
        """, (request_id,))

        docs = db.fetchall()

        new_status = get_submission_status(docs)
        db.execute("UPDATE requests SET status = %s WHERE id = %s", (new_status, request_id))
        con.commit()

        # email the submitter
        db.execute("SELECT name, submitter_id, id FROM requests WHERE id = %s", (request_id,))
        request_info = db.fetchone()

        db.execute("SELECT email FROM submitting_users WHERE id = %s", (request_info["submitter_id"],))
        submitter_email = db.fetchone()

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

    return render_template("review_submission.html", docs=docs_to_display, token=token, user_name=user_name, req=req_data)


# review expiring docs
@app.route("/expiration", methods=['GET', 'POST'])
def expiration():

    # call db
    db = get_db().cursor()

    # get current user
    user_id = session.get("id")
    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    # get current user docs
    db.execute("SELECT * FROM docs WHERE admin_user_id = %s", (user_id,))
    docs = db.fetchall()

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
            pass
            
    
    # sorts the list by expiry date, putting closest/oldest first
    expiring.sort(key=lambda doc: datetime.strptime(doc["expiry_date"], "%Y-%m-%d").date())
                
    return render_template("expiration.html", expiring=expiring, user_name=user_name)







### ADMIN HELPER ROUTES ###



# removes sub from the db when "delete" button is hit
@app.route("/delete_sub", methods=['POST'])
def delete_sub():
    # call db
    con = get_db()
    db = get_db().cursor()
    # gets user's token
    admin_id = session.get("id")
    token = request.form.get("token")
    db.execute("SELECT name, id FROM submitting_users WHERE token = %s", (token,))
    sub = db.fetchone()
    

    # if got, deletes this user from the db
    if token:
        flash(f"Submitter {sub['name']} has been successfully deleted.")
        db.execute("DELETE FROM admin_submitters WHERE admin_id = %s AND submitter_id = %s", (admin_id, sub["id"]))
        con.commit()
        
    return redirect("/my_submitters")

# delete docs from library
@app.route("/del_doc/<id>", methods=['POST'])
def del_doc(id):

    con = get_db()
    db = get_db().cursor()

    db.execute("DELETE FROM users_docs WHERE id = %s", (id,))
    con.commit()

    return redirect("/documents_library")


# review all submission of a project
@app.route("/project_summary/<id>")
def project_summary(id):


    db = get_db().cursor()
    user_id = session.get("id")

    db.execute("SELECT project_admin_id FROM project WHERE id = %s", (id,))
    user = db.fetchone()

    db.execute("SELECT login FROM admin_users WHERE id = %s", (user_id,))
    user_name = db.fetchone()

    if not user or session.get("id") != user["project_admin_id"]:
        return redirect("/login")
    
    db.execute(
        """
    SELECT
    project.project_name,
    project.project_number,
    requests.name AS req_name,
    requests.token,
    requests.status,
    requests.submitter_id,
    submitting_users.name AS sub_name
    FROM requests
    JOIN project ON project.id = requests.project_id
    JOIN submitting_users ON submitting_users.id = requests.submitter_id
    WHERE project.id = %s
    """, (id))

    submissions = db.fetchall()


    return render_template("project_summary.html", submissions=submissions, user_name=user_name)




@app.route("/download/<int:doc_id>")

def download(doc_id):

    # get current user
    user_id = session.get("id")
    
    # redirects if none
    if not user_id:
        return redirect("/login")

    db = get_db().cursor()
    
    db.execute("SELECT link, admin_user_id, submitting_user_id FROM docs WHERE id = %s", (doc_id,))
    doc = db.fetchone()

    if not doc:
        return "File not found", 404

    if user_id != doc["admin_user_id"] and user_id != doc["submitting_user_id"]:
        abort(403)
        
    
    s3_key = doc["link"]

    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )

    try:
        presigned_url = s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": os.getenv("S3_BUCKET_NAME"),
                "Key": s3_key
            },
            ExpiresIn=3600  # 1 hour link
        )
        return redirect(presigned_url)

    except Exception as e:
        print("Error generating URL:", e)
        return "Something went wrong", 500
    
@app.route("/download_submission/<int:request_id>")
def download_submission(request_id):

    user_id = session.get("id")
    if not user_id:
        return redirect("/login")

    db = get_db().cursor()
    db.execute("SELECT * FROM docs WHERE request_id = %s", (request_id,))
    docs = db.fetchall()

    if not docs:
        return "No documents found", 404

    # Ensure the user is the admin who owns this request
    if docs[0]["admin_user_id"] != user_id:
        abort(403)

    # Set up S3 client
    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )

    # Create in-memory zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zipf:
        for doc in docs:
            key = doc["link"]  # this is the path in S3
            file_obj = io.BytesIO()

            try:
                s3.download_fileobj(os.getenv("S3_BUCKET_NAME"), key, file_obj)
                file_obj.seek(0)
                filename = key.split("/")[-1]
                zipf.writestr(filename, file_obj.read())
            except Exception as e:
                print(f"Error downloading {key}: {e}")

    zip_buffer.seek(0)

    return send_file(
        zip_buffer,
        mimetype="application/zip",
        as_attachment=True,
        download_name=f"submission_{request_id}.zip"
    )



### SUBMITTER REGISTRATION AND LOGIN ###



@app.route("/submitter_registration/<token>", methods=["GET", "POST"])
def submitter_registration(token):

    con = get_db()
    db = get_db().cursor()
    db.execute("SELECT * FROM submitting_users WHERE token = %s", (token,))
    submitter = db.fetchone()

    if request.method == "POST":

        # getting new credentials 
        login = request.form.get("login")
        password = request.form.get("password")
        password2 = request.form.get("password2")
        company_name = request.form.get("company_name")
        description = request.form.get("description")
        email = request.form.get("email")
        phone = request.form.get("phone")
        address = request.form.get("address")

        if not request.form.get("agree"):
            return "You must agree to the Privacy Policy and Terms of Service.", 400


        if login and password and password2 and submitter:
            if password == password2:
                
                hashed_password = generate_password_hash(password)
                

            # create new user in db
                db.execute("UPDATE submitting_users SET login = %s, password = %s, name = %s, description = %s, email = %s, phone = %s, address = %s WHERE token = %s", (login, hashed_password, company_name, description, email, phone, address, token))
                con.commit()
                db.execute("UPDATE admin_users SET login = %s, password = %s, name = %s, description = %s, email = %s, phone = %s, address = %s WHERE token = %s", (login, hashed_password, company_name, description, email, phone, address, token))
                con.commit()

                # sands back to login
                return redirect("/submitter_login")

    # rendering registration page       
    return render_template("submitter_registration.html", submitter=submitter)



@app.route("/submitter_login", methods=["GET", "POST"])
def submitter_login():

    # calls db

    db = get_db().cursor()

    if request.method == "POST":
        
        # request information through forms
        login = request.form.get("login")
        password = request.form.get("password")

        db.execute("SELECT * FROM submitting_users WHERE login = %s", (login,))
        user = db.fetchone()

        if user and check_password_hash(user["password"], password):

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
    db = get_db().cursor()
    submitter_id = session.get("id")

    db.execute("SELECT * FROM submitting_users WHERE id = %s", (submitter_id,))
    sub_user = db.fetchone()
    

    # redirect if not logged in
    if not submitter_id and not session.get("submitter"):
        return redirect("/submitter_login")

    # get submitter
    db.execute("SELECT * FROM submitting_users WHERE id = %s", (submitter_id,))
    submitter = db.fetchone()

    # get information about request to display
    db.execute("""
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
    WHERE requests.submitter_id = %s
""", (submitter_id,))
    
    sub_requests = db.fetchall()

    return render_template("submitter_dashboard.html", submitter=submitter, sub_requests=sub_requests, sub_user=sub_user)



# page for the submission of the documents by the request
@app.route("/submission/<token>", methods=['GET', 'POST'])
def submission(token):

    
    # call db
    con = get_db()
    db = get_db().cursor()

    submitter_id = session.get("id")
    
    db.execute("SELECT * FROM submitting_users WHERE id = %s", (submitter_id,))
    sub_user = db.fetchone()

    # get data of the request
    db.execute("SELECT * FROM requests WHERE token = %s", (token,))
    doc_request = db.fetchone()

    # get project name to display
    db.execute("SELECT project_name, id FROM project WHERE id = %s", (doc_request["project_id"],))
    project_name = db.fetchone()

    # check in case token is not valid
    if not doc_request:
        return "Invalid token", 404

    # get all required docs for this user
    db.execute("SELECT * FROM requirements WHERE set_id = %s", (doc_request["requirement_set_id"],))
    required_docs = db.fetchall()

    
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

                
                # get provided file name
                raw_filename = file.filename

                # secure filename
                sec_filename = secure_filename(raw_filename)
                
                # assign file name in readable format
                filename = f"{session['id']}_{doc_type}_{sec_filename}"
                # join upload folder and new file name
                filepath = f"{doc_request['admin_id']}/{doc_request['project_id']}/{doc_request['submitter_id']}/"
                # saves expiry date
                expiry = request.form.get(f"{doc_type}_expiry")
                # saves the file
                

                s3_path = upload_file_to_s3(file, filename, filepath)

                # gets doc revision
                db.execute("SELECT revision FROM docs WHERE request_id = %s and doc_type = %s", (doc_request['id'], doc_type))
                revision = db.fetchone()
                
                if revision:
                    rev = revision["revision"] + 1
                    # cleans up old doc submission in case re-submission is required
                    db.execute("DELETE FROM docs WHERE request_id = %s AND doc_type = %s", (doc_request["id"], doc_type))

                else:
                    rev = 0

                # adds information about this submission to db
                db.execute("INSERT INTO docs (submitting_user_id, link, date_submitted, expiry_date, confirmation , doc_type, request_id, admin_user_id, doc_status, filepath, revision, expiry_required) VALUES (%s, %s, %s, %s, 'pending', %s, %s, %s, %s, %s, %s, %s)", (session['id'], s3_path, datetime.now(), expiry, doc_type, doc_request["id"], doc_request["admin_id"], "pending_review", filepath, rev, doc["expiry_required"]))

        con.commit()

        # email to admin
        db.execute("SELECT name FROM submitting_users WHERE id = %s", (session.get('id'),))
        sub = db.fetchone()

        db.execute("SELECT * FROM admin_users WHERE id = %s", (doc_request['admin_id'],))
        admin = db.fetchone()



        subject = f"Documents submitted: Request {doc_request['name']} for {project_name['project_name']}"
        text_body = f"Documents submitted: Request {doc_request['name']} for {project_name['project_name']}"

        html_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                    <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                        <h2>Submission Completed</h2>
                        <p>Submission <strong>{doc_request['name']}</strong> for the project <strong>{project_name['project_name']}</strong> has been completed by <strong>{sub['name']}.</strong> </p>
                        <p>Please log in to your dashboard to view the details.</p>
                        <a href="http://127.0.0.1:5000/login"
                            style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                            Go to Dashboard
                        </a>
                    </div>
                </body>
            </html>
        """

        send_email(admin['email'], subject, text_body, html_body, email_password)



    # get submitted docs for this request
    db.execute("SELECT * FROM docs WHERE request_id = %s", (doc_request["id"],))
    submitted_docs = db.fetchall()

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
                "id": None,
                "expiry_required": req["expiry_required"]
            })
    
        
    return render_template("submission.html", project_name=project_name, doc_request=doc_request, required_docs=docs_to_display, sub_user=sub_user)





### SUBMITTER HELPER ROUTES ###



# enables sub to delete file
@app.route("/delete_doc/<doc_id>", methods=['POST'])
def delete_doc(doc_id):

    con = get_db()
    db = get_db().cursor()

    # get's id of the submitter that uploaded the file
    db.execute("SELECT id, submitting_user_id, filepath FROM docs WHERE id = %s", (doc_id,))
    doc = db.fetchone()

    # checks against currect session id and block unauthorized attempts
    if not session.get("id") or session.get("id") != doc["submitting_user_id"]:
        return "Unauthorized", 403
    
    else:
        # get token of the submission of the file that is beigh deleted
        
        db.execute("""
        SELECT requests.token
        FROM requests
        JOIN docs ON docs.request_id = requests.id
        WHERE docs.id = %s
        """, (doc_id,))
        token = db.fetchone()


        # adds record of the deleted file to the db
        db.execute("INSERT INTO deleted_docs (original_doc_id, submitter_id, filepath) VALUES (%s, %s, %s)", (doc["id"], doc["submitting_user_id"], doc["filepath"]))

        # deletes actual file
        if doc and doc["filepath"]:
            try:
                os.remove(doc["filepath"])
            except Exception as e:
                print(f"Error deleting file: {e}")


        # removes file from docs
        db.execute("DELETE FROM docs WHERE id = %s", (doc_id,))
        con.commit()

        flash("Document deleted successfully.")

        return redirect(f"/submission/{token['token']}")
    



@app.route("/company_information", methods=['GET', 'POST'])
def company_information():

    # connect db
    con = get_db()
    db = get_db().cursor()

    

    # get current user id
    user_id = session.get("id")
    db.execute("SELECT * FROM admin_users WHERE id = %s", (user_id,))
    admin_user = db.fetchone()

    db.execute("SELECT * FROM submitting_users WHERE id = %s", (user_id,))
    sub_user = db.fetchone()


    if admin_user:
        user = admin_user
        role = "admin"
    elif sub_user:
        user = sub_user
        role = "sub"
    else:
        return redirect("/login")
    
    # redirects to login if none
    if not user_id:
        return redirect("/login")

    if request.method == "POST":

        # collects new info
        name = request.form.get("company_name")
        description = request.form.get("company_information")
        email = request.form.get("email")
        address = request.form.get("address")
        phone = request.form.get("phone")

        db.execute("SELECT * FROM admin_users WHERE email = %s OR phone = %s", (email, phone))
        existing = db.fetchall()

        if existing:
            return "This email or number is already in use.", 404

        # inserts into db
        db.execute("UPDATE admin_users SET name = %s, description = %s, email = %s, address = %s, phone = %s WHERE token = %s", (name, description, email, address, phone, user['token']))
        db.execute("UPDATE submitting_users SET name = %s, description = %s, email = %s, address = %s, phone = %s WHERE token = %s", (name, description, email, address, phone, user['token']))
        con.commit()
        flash("Information successfully updated.")

    if role == "admin":
        return render_template("company_information.html", user=user)
    else:
        return render_template("sub_company_information.html", user=user)

    






def expiry_notification():

    con = get_db()
    db = get_db().cursor()

    today = date.today()

    db.execute("""
        SELECT
            docs.id,
            docs.doc_type,
            docs.expiry_date,
            admin_users.name AS admin_name,
            admin_users.email AS admin_email,
            submitting_users.name AS sub_name,
            submitting_users.email AS sub_email,
            requests.id AS req_id,
            requests.name AS request_name,
            requests.token
        FROM docs
            JOIN admin_users ON admin_users.id = docs.admin_user_id
            JOIN submitting_users ON submitting_users.id = docs.submitting_user_id
            JOIN requests ON requests.id = docs.request_id
        """)
    
    docs = db.fetchall()
    
    for doc in docs:

        # tries to format expiry date
        try:
            expiry = datetime.strptime(doc["expiry_date"], "%Y-%m-%d").date()

        # if fails - skips the doc
        except(ValueError, TypeError):
            continue


        if expiry == today + timedelta(days=7):


            # email warning to admin

            subject = f"Document {doc['doc_type']} submitted for {doc['request_name']} is about to expire."
            text_body = f"Document {doc['doc_type']} submitted for {doc['request_name']} is about to expire."

            html_body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                        <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                            <h2>Document is about to expire.</h2>
                            <p>Document <strong>{doc['doc_type']}</strong> submitted by <strong>{doc['sub_name']}</strong> for <strong>{doc['request_name']}</strong> is about to expire.</p>
                            <p>Please log in to your dashboard to view the details.</p>
                            <a href="http://127.0.0.1:5000/login"
                                style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                                Go to Dashboard
                            </a>
                        </div>
                    </body>
                </html>
            """

            send_email(doc['admin_email'], subject, text_body, html_body, email_password)

        # email warning to sub

            subject = f"Document {doc['doc_type']} submitted for {doc['request_name']} is about to expire."
            text_body = f"Document {doc['doc_type']} submitted for {doc['request_name']} is about to expire."

            html_body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                        <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                            <h2>Document is about to expire.</h2>
                            <p>Document <strong>{doc['doc_type']}</strong> submitted to <strong>{doc['admin_name']}</strong> for <strong>{doc['request_name']}</strong> is about to expire.</p>
                            <p>Please log in to your dashboard to view the details.</p>
                            <a href="http://127.0.0.1:5000/submitter_login"
                                style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                                Go to Dashboard
                            </a>
                        </div>
                    </body>
                </html>
            """

            send_email(doc['sub_email'], subject, text_body, html_body, email_password)

            # updates expiring doc status to action required
            db.execute("UPDATE docs SET doc_status = %s WHERE id = %s", ('action_required', doc['id']))


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
                WHERE requests.id = %s
            """, (doc['req_id'],)).fetchall()

            # gets full request status and updates it
            submission_status = get_submission_status(docs)

            db.execute("UPDATE requests SET status = %s WHERE id = %s", (submission_status, doc['req_id']))
            con.commit()

        
        elif expiry == today:

             # email warning to admin

            subject = f"Document {doc['doc_type']} submitted for {doc['request_name']} has expired."
            text_body = f"Document {doc['doc_type']} submitted for {doc['request_name']} has expired."

            html_body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                        <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                            <h2>Document is about to expire.</h2>
                            <p>Document <strong>{doc['doc_type']}</strong> submitted by <strong>{doc['sub_name']}</strong> for <strong>{doc['request_name']}</strong> has expired.</p>
                            <p>Please log in to your dashboard to view the details.</p>
                            <a href="http://127.0.0.1:5000/login"
                                style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                                Go to Dashboard
                            </a>
                        </div>
                    </body>
                </html>
            """

            # email to sub
            send_email(doc['admin_email'], subject, text_body, html_body, email_password)


            html_body = f"""
                <html>
                    <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                        <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                            <h2>Document is about to expire.</h2>
                            <p>Document <strong>{doc['doc_type']}</strong> submitted to <strong>{doc['admin_name']}</strong> for <strong>{doc['request_name']}</strong> has expired.</p>
                            <p>Please log in to your dashboard to view the details.</p>
                            <a href="http://127.0.0.1:5000/submitter_login"
                                style="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">
                                Go to Dashboard
                            </a>
                        </div>
                    </body>
                </html>
            """

            send_email(doc['sub_email'], subject, text_body, html_body, email_password)




### TRANSITIONS ###

@app.route("/admin_sub/")
def admin_sub():

    db = get_db().cursor()

    # checking who is logged

    user_id = session.get("id")

    if session.get("admin") == True:

        db.execute("SELECT token FROM admin_users WHERE id = %s", (user_id,))
        token = db.fetchone()

        db.execute("SELECT * FROM submitting_users WHERE token = %s", (token["token"],))
        sub = db.fetchone()

        if sub:
            session.clear()
            session["submitter"] = True
            session["id"] = sub["id"]
            return redirect("/submitter_dashboard")
        else:
            return redirect("/login")

    elif session.get("submitter") == True:
        db.execute("SELECT token FROM submitting_users WHERE id = %s", (user_id,))
        token = db.fetchone()

        db.execute("SELECT * FROM admin_users WHERE token = %s", (token["token"],))
        admin = db.fetchone()

        if admin:
            session.clear()
            session["admin"] = True
            session["id"] = admin["id"]
            return redirect("/admin")
        else:
            return redirect("/login")
        
    else:
        return redirect("/login")


### MISC ###

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms_of_service")
def service():
    return render_template("terms_of_service.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/debug/admins")
def debug_admins():
    db = get_db().cursor()
    db.execute("SELECT id, name, email FROM admin_users LIMIT 10")
    admins = db.fetchall()

    return json.dumps(admins, indent=2)




# schedule to run flag_expiry every 24 hours
scheduler = BackgroundScheduler()
scheduler.add_job(func=expiry_notification, trigger='interval', hours=24)
scheduler.start()

atexit.register(lambda: scheduler.shutdown())