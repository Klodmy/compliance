import smtplib
from email.message import EmailMessage


def main():
    pass


# checks file names to define if submitted format is allowed
def ex_check(name, allowed):
    for ex in allowed:
        if name.endswith(f".{ex.lower()}"):
            return True
    return False


# connects to gmail and sends an email
def send_email(send_from, send_to, subject, body, password, token):
    email = EmailMessage()
    email["From"] = "dk.ads24@gmail.com"
    email["To"] = send_to
    email["Subject"] = subject
    email.set_content(body)
    email.add_alternative(
        f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.5; color: #333;">
                <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #eee; border-radius: 6px;">
                    <h2 style="color: #444;">You have a new submittal request from <span style="color: #007bff;">{send_from}</span></h2>
                    <p>Please log in to your dashboard to review the request.</p>
                    <a href="http://127.0.0.1:5000/submitter_registration/{token}"
                    tyle="display: inline-block; background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">Login to Dashboard</a>
                </div>
            </body>
        </html>
        """,
    subtype="html"
    )
    
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smpt:
        smpt.login("dk.ads24@gmail.com", password)
        smpt.send_message(email)


# checks submission status based on statuses of docs
def get_submission_status(docs):

    submitted_with_files = []
    approved = []

    # checks number of submitted docs
    for doc in docs:
        if doc['link']:
            submitted_with_files.append(doc)

        if doc['doc_status'] == "approved":
            approved.append(doc)

        if doc['doc_status'] == "action_required":
            return "action_required"
        

    if len(submitted_with_files) == 0:
        print("1")
        return "pending_submission"
    
    elif len(submitted_with_files) < len(docs):
        print("2")
        return "partially_submitted"
    
    elif len(approved) == len(docs):
        print("3")
        return "approved"
    
    else:
        print("4")
        return "pending_review"
    
    




if __name__ == "__main__":
    main()
