import os
import boto3

DATABASE_URL = os.environ["DATABASE_URL"]
s3 = boto3.client("s3")  # credentials come from the instance role
