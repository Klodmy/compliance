import smtplib
from email.message import EmailMessage
import os
import boto3
from werkzeug.utils import secure_filename

def main():
    pass


# checks file names to define if submitted format is allowed
def ex_check(name, allowed):
    name = name.lower()
    for ex in allowed:
        if name.endswith(f".{ex.lower()}"):
            return True
    return False


# connects to gmail and sends an email
def send_email(send_to, subject, body, html_body, password):
    email = EmailMessage()
    email["From"] = "dk.ads24@gmail.com"
    email["To"] = send_to
    email["Subject"] = subject
    email.set_content(body)
    email.add_alternative(html_body, subtype="html")
    
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smpt:
        smpt.login("dk.ads24@gmail.com", password)
        smpt.send_message(email)


# checks submission status based on statuses of docs
def get_submission_status(docs):

    submitted_with_files = []
    approved = []

    # checks number of submitted docs and approved docs, returns action required if at least 1 doc has this status
    for doc in docs:
        if doc['link']:
            submitted_with_files.append(doc)

        if doc['doc_status'] == "approved":
            approved.append(doc)

        if doc['doc_status'] == "action_required":
            return "action_required"
        

    # if non docs submitted 
    if len(submitted_with_files) == 0:
        return "pending_submission"
    
    # if submitted less then requested
    elif len(submitted_with_files) < len(docs):
        return "partially_submitted"
    
    # if all docs are approved
    elif len(approved) == len(docs):
        return "approved"
    
    # other cases
    else:
        return "pending_review"
    

# saving files to s3
# getting envvars
s3 = boto3.client("s3", aws_access_key_id = os.getenv("AWS_ACCSS_KEY_ID"),  aws_secret_access_key = os.getenv("AWS_SECRET_ACCESS_KEY"), region_name = os.getenv("AWS_REGION"))
          
BUCKET_NAME = os.getenv("S3_BUCKET_NAME")

# gets file, name and folders and puts into bucket
def upload_file_to_s3(file_obj, filename, path_prefix):

    s3_path = f"{path_prefix}/{filename}"

    s3.upload_fileobj(file_obj, BUCKET_NAME, s3_path)

    # returns a name to store
    return s3_path


if __name__ == "__main__":
    main()
