import json
import boto3
import logging
from functions import get_ssm_parameter, get_aws_accounts, send_alert

def lambda_handler(event, context):
    try:
        # Retrieve Account Alias
        account_alias = get_ssm_parameter("/global/account/alias")

        # Extract bucket name and bucket policy from the CloudTrail event
        bucket_name, bucket_policy = extract_policy_details(event)

        # Ensure bucket_policy is a dictionary
        if isinstance(bucket_policy, str):
            bucket_policy = json.loads(bucket_policy)

        # Send notification if unauthorized accounts are found
        send_alert(event, bucket_policy, f"Unauthorized access detected in {bucket_name} in account {account_alias}")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

def extract_policy_details(event):
    """Extracts and returns bucket name and policy from the event using direct indexing for mandatory fields."""
    try:
        bucket_name = event['detail']['requestParameters']['bucketName']
        bucket_policy = event['detail']['requestParameters']['bucketPolicy']
    except KeyError as e:
        logging.error(f"Missing key in event data: {str(e)}")
        raise
    return bucket_name, bucket_policy








import boto3
import logging

def send_alert(event, bucket_policy, SNSMessage):
    # Initialize clients
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    username = event['detail']['userIdentity']['arn']

    # Fetch the list of authorized accounts
    authorized_accounts = get_aws_accounts()

    # Check for unauthorized accounts in the bucket policy
    unauthorized_found = []
    for statement in bucket_policy.get('Statement', []):
        principal = statement.get('Principal', {})
        if 'AWS' in principal:
            aws_accounts = principal['AWS']
            if isinstance(aws_accounts, str):
                aws_accounts = [aws_accounts]
            for account in aws_accounts:
                account_id_extracted = account.split(':')[-2]
                if account_id_extracted not in authorized_accounts:
                    unauthorized_found.append(account_id_extracted)

    # Send SNS message if unauthorized accounts are found
    if unauthorized_found:
        sns_client = boto3.client('sns')
        sns_topic_arn = f"arn:aws:sns:us-east-1:{account_id}:IAM_Role_Notifications"
        unauthorized_accounts_str = ', '.join(unauthorized_found)
        message = f"{SNSMessage}: Unauthorized account(s) {unauthorized_accounts_str} detected. Role updated by user: {username}."
        
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=message
        )
        logging.info(f"Alert sent: {message}")
    else:
        logging.info("No unauthorized accounts found.")


