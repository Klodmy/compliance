#ConComply
ConComply is a lightweight compliance management tool built for general contractors and subcontractors. It helps streamline the document collection process by allowing admins to request and review compliance documents, while subcontractors can upload and track submissions easily.

##Features:

- Admin dashboard to create and manage document requests
- Subcontractor access via secure tokenized links
- File uploads to AWS S3
- Document status tracking (Pending Review, Approved, Action Required)
- Email notifications on document requests and expiry reminders
- Expiration date tracking with automated reminders
- Zip download of entire document submissions
- PostgreSQL database
- Role-based access (Admin and Submitting User)

##Tech Stack:
- Python / Flask
- PostgreSQL
- Jinja2 templating
- AWS S3 (file storage)
- APScheduler (background tasks for reminders)
- Deployed with Render

Notes:
- This is an open beta version.
- No guarantees of uptime or data retention.
- Please don’t use it for critical data (yet).
- For feedback: beta.concomply@gmail.com