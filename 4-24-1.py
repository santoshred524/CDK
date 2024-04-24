import json
import boto3

def lambda_handler(event, context):
    try:
        # Initialize AWS clients
        sns_client = boto3.client('sns')
        sts_client = boto3.client('sts')

        # Get the current AWS account ID
        account_id = sts_client.get_caller_identity()["Account"]

        # Define authorized account IDs
        authorized_accounts = ['123456789012', '234567890123', '345678901234']

        # Extract the bucket name and bucket policy from the CloudTrail event
        if 'detail' in event and 'requestParameters' in event['detail']:
            bucket_name = event['detail']['requestParameters'].get('bucketName', '')
            bucket_policy = event['detail']['requestParameters'].get('bucketPolicy', {})

            print(f"Scanning bucket policy for bucket: {bucket_name}")

            # Initialize a list to collect unauthorized account findings
            unauthorized_found = []

            # Scan each statement in the bucket policy
            for statement in bucket_policy.get('Statement', []):
                principal = statement.get('Principal', {})
                
                if isinstance(principal, dict) and 'AWS' in principal:
                    aws_accounts = principal['AWS']
                    if not isinstance(aws_accounts, list):
                        aws_accounts = [aws_accounts]  # Ensure aws_accounts is a list

                    # Check each AWS account in the principal field
                    for account in aws_accounts:
                        account_id_extracted = account.split(':')[-1]
                        if account_id_extracted not in authorized_accounts:
                            unauthorized_found.append(account_id_extracted)
                            print(f"Unauthorized account {account_id_extracted} detected in bucket policy.")

            # Send notification if unauthorized accounts are found
            if unauthorized_found:
                sns_topic_arn = f"arn:aws:sns:{event['region']}:{account_id}:Bucket_Policy_Alert"
                sns_client.publish(
                    TopicArn=sns_topic_arn,
                    Message=f"Unauthorized account(s) {unauthorized_found} detected in bucket policy of {bucket_name}."
                )
                print("Notification sent for unauthorized accounts found in bucket policy.")
            else:
                print("No unauthorized accounts found in bucket policy.")
        else:
            print("No bucket policy change detected or missing necessary event details.")

    except Exception as e:
        print(f"Error: {str(e)}")
        raise e
