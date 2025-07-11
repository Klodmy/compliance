import boto3
import os

s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_REGION")
)

print("BUCKET_NAME env var is:", os.getenv("S3_BUCKET_NAME"))
print("key:", os.getenv("AWS_ACCESS_KEY_ID"))

# replace with your real bucket name
bucket_name = os.getenv("S3_BUCKET_NAME")

# test list
print("Testing access to bucket:", bucket_name)
response = s3.list_objects_v2(Bucket=bucket_name)
print("Bucket contents:", response.get("Contents"))