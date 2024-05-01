[ERROR] TypeError: string indices must be integers, not 'str'
Traceback (most recent call last):
  File "/var/task/s3_policy.py", line 22, in lambda_handler
    send_alert(event, account_alias, f"Unauthorized access detected in {bucket_name} in account {account_alias}")
  File "/var/task/functions.py", line 36, in send_alert
    for statement in parsed_data["Statement"]:



[ERROR] TypeError: 'NoneType' object is not subscriptable
Traceback (most recent call last):
  File "/var/task/s3_policy.py", line 22, in lambda_handler
    send_alert(event, bucket_policy, f"Unauthorized access detected in {bucket_name} in account {account_alias}")
  File "/var/task/functions.py", line 36, in send_alert
    for statement in parsed_data["Statement"]:







import json
import boto3
import logging
from functions import get_ssm_parameter, get_aws_accounts, send_alert
from office365.runtime.auth.user_credential import UserCredential
from office365.sharepoint.client_context import ClientContext

def lambda_handler(event, context):
    try:
        # Retrieve Account Alias and Authorized Accounts
        account_alias = get_ssm_parameter("/global/account/alias")
        authorized_accounts = get_aws_accounts()

        # Extract bucket name and bucket policy from the CloudTrail event
        bucket_name, bucket_policy = extract_policy_details(event)

        # Ensure bucket_policy is a dictionary
        if isinstance(bucket_policy, str):
            bucket_policy = json.loads(bucket_policy)

        # Send notification if unauthorized accounts are found
        send_alert(event, parsed_data, f"Unauthorized access detected in {bucket_name} in account {account_alias}")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

def extract_policy_details(event):
    """Extracts and returns bucket name and policy from the event."""
    try:
        bucket_name = event['detail']['requestParameters']['bucketName']
        
        # Accessing bucketPolicy 
        if 'bucketPolicy' in event['detail']['requestParameters']:
            bucket_policy = event['detail']['requestParameters']['bucketPolicy']
        else:
            logging.error("No 'bucketPolicy' key found in event data")
            return bucket_name, None
        
    except KeyError as e:
        logging.error(f"Missing key in event data: {str(e)}")
        raise
    
    return bucket_name, bucket_policy
