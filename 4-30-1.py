import boto3
from office365.runtime.auth.user_credential import UserCredential
from office365.sharepoint.client_context import ClientContext

def get_ssm_parameter(parameter_name):
    ssm_client = boto3.client("ssm")
    response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
    parameter_info = response["Parameter"]
    parameter_value = parameter_info["Value"]
    return parameter_value

def get_aws_accounts() -> list:
    secretmanager= boto3.client('secretsmanager')
    password_raw = secretmanager.get_secret_value(SecretId='arn:aws:secretsmanager:us-east-1:107872598712:secret:account_policy_lambda-GH2Jwz')
    password = password_raw['SecretString']
    list_collection = ClientContext("https://emcins.sharepoint.com/sites/TechOps-CloudEngineering").with_credentials(UserCredential('SA-PShareptLambda@emcins.com',password)).web.lists
    
    aws_account_list = list_collection.get_by_title('AWS Accounts')
    aws_accounts = aws_account_list.items.get().execute_query()

    account_list = []
    for item in aws_accounts:
        account_list.append(item.properties['Title'])
    return account_list

def send_alert(event, parsed_data, SNSMessage):
    #Get Account Id
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    username = event['detail']['userIdentity']['arn']

     # Check if the trust policy contains an unauthorized account
    combined =[]
    authorized_account = get_aws_accounts()        
            
    for statement in parsed_data["Statement"]:
        raw = statement["Principal"]["AWS"].split(":")
        principal = statement["Principal"]["AWS"].replace('"', '')
        if len(raw) >= 2:
            print("principal is in arn format")
            principal = principal.split(":")[4]
        if principal not in authorized_account:
            print(f"{principal} is not authorized")
            combined.append(principal)
        else:
            print(f"{principal} is authorized")
    #Send email
    if combined:
        sns_topic_arn = f"arn:aws:sns:us-east-1:{account_id}:IAM_Role_Notifications"
        sns_client = boto3.client('sns')
        sns_client.publish(
            TopicArn=sns_topic_arn,
            Message=f"""{SNSMessage}: 
{combined}.

Role updated by user: {username}."""
        )
    return






import json
import boto3
from office365.runtime.auth.user_credential import UserCredential
from office365.sharepoint.client_context import ClientContext
import functions
import logging

# Initialize AWS clients
sts_client = boto3.client('sts')

# Define authorized account IDs
authorized_accounts = ['181541285741', '642282818489', '147483137759', '512761343058', '309492738658', '452933866978', '730558103591', '107872598712', '567820090735', '028544375379', '384267352821', '317773170705', '834975220471', '508522129891', '149834317114', '283274754567', '957488187883', '310476877601', '800184284482']

def lambda_handler(event, context):
    try:
        # Get Account Alias and Account ID
        account_alias = functions.get_ssm_parameter("/global/account/alias")
        account_id = sts_client.get_caller_identity()["Account"]

        # Extract bucket name and bucket policy from the CloudTrail event
        bucket_name, bucket_policy = extract_policy_details(event)
        
        # Check for unauthorized account access
        unauthorized_found = check_unauthorized_access(bucket_policy)

        # Send notification if unauthorized accounts are found
        if unauthorized_found:
            message = (f"Unauthorized account(s) {unauthorized_found} detected in bucket policy "
                       f"of {bucket_name} in account {account_alias}.")
            functions.send_alert(event['region'], account_id, message)
        else:
            logging.info("No unauthorized accounts found in bucket policy.")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

def extract_policy_details(event):
    """Extracts and returns bucket name and policy from the event."""
    bucket_name = event.get('detail', {}).get('requestParameters', {}).get('bucketName', '')
    bucket_policy = event.get('detail', {}).get('requestParameters', {}).get('bucketPolicy', {})
    return bucket_name, bucket_policy

def check_unauthorized_access(bucket_policy):
    """Checks for unauthorized AWS accounts in the bucket policy."""
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
    return unauthorized_found
