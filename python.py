import json
import boto3

def lambda_handler(event, context):
    try:
        # Initialize AWS clients
        s3_client = boto3.client('s3')
        sns_client = boto3.client('sns')
        sts_client = boto3.client('sts')

        # Get the current AWS account ID
        account_id = sts_client.get_caller_identity()["Account"]

        # Define unauthorized account IDs
        unauthorized_accounts = ['123456789012', '234567890123', '345678901234']

        # Extract relevant data from the CloudTrail event
        bucket_name = event['detail']['requestParameters']['bucketName']
        event_name = event['detail']['eventName']

        # Check if the event is a PutBucketPolicy action
        if event_name == 'PutBucketPolicy':
            print(f"Checking bucket policy for unauthorized accounts in Bucket: {bucket_name}")

            # Fetch the current bucket policy directly from the S3 bucket
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(policy['Policy'])
            
            # Initialize a list to collect unauthorized account findings
            unauthorized_found = []

            # Scan each statement in the policy document
            for statement in policy_document.get('Statement', []):
                principal = statement.get('Principal', {})
                
                if isinstance(principal, dict) and 'AWS' in principal:
                    aws_accounts = principal['AWS']
                    if not isinstance(aws_accounts, list):
                        aws_accounts = [aws_accounts]  # Ensure aws_accounts is a list

                    # Check each AWS account in the principal field
                    for account in aws_accounts:
                        account_id_extracted = account.split(':')[-1]
                        if account_id_extracted in unauthorized_accounts:
                            unauthorized_found.append(account_id_extracted)
                            print(f"Unauthorized account {account_id_extracted} detected in bucket policy.")
            
            # Send notification if unauthorized accounts are found
            if unauthorized_found:
                sns_topic_arn = f"arn:aws:sns:us-east-1:{account_id}:Bucket_Policy_Alert"
                sns_client.publish(
                    TopicArn=sns_topic_arn,
                    Message=f"Unauthorized account(s) {unauthorized_found} detected in bucket policy of {bucket_name}."
                )
                print("Notification sent for unauthorized accounts found in bucket policy.")
            else:
                print("No unauthorized accounts found in bucket policy.")

    except Exception as e:
        print(f"Error: {str(e)}")
        raise e





{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": ["PutBucketPolicy", "DeleteBucketPolicy"]
  }
}



