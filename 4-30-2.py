this is my functions.py where all the functions have been defined :

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




this is my lambda code to look for unauthorized accounts in the s3 bucket policy :

import json
import boto3
import functions
import logging
from office365.runtime.auth.user_credential import UserCredential
from office365.sharepoint.client_context import ClientContext    

-> Instead of importing the whole functions module, lets just import what we need out of it.
from functions import get_ssm_parameter, send_alert

def lambda_handler(event, context):
    try:
        # Retrieve Account Alias and Authorized Accounts
        account_alias = functions.get_ssm_parameter("/global/account/alias")
        authorized_accounts = functions.get_aws_accounts()  

        # Extract bucket name and bucket policy from the CloudTrail event
        bucket_name, bucket_policy = extract_policy_details(event)
        
        # Check for unauthorized account access
        unauthorized_found = check_unauthorized_access(bucket_policy, authorized_accounts)

        # Send notification if unauthorized accounts are found
        if unauthorized_found:
            message = (f"Unauthorized account(s) {unauthorized_found} detected in bucket policy "
                       f"of {bucket_name} in account {account_alias}.")
            functions.send_alert(event, account_alias, message)
        else:
            logging.info("No unauthorized accounts found in bucket policy.")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

def extract_policy_details(event):
    """Extracts and returns bucket name and policy from the event."""
    bucket_name = event.get('detail', {}).get('requestParameters', {}).get('bucketName', '')   -> instead of using .get() to access dictionary values, we should be using square brackets event['detail']['requestParameters']['bucketName']
.get() won't throw an error if a key doesn't exist in the dictionary which makes it hard to determine the actual source of an error if the key doesn't exist
    bucket_policy = event.get('detail', {}).get('requestParameters', {}).get('bucketPolicy', {})
    return bucket_name, bucket_policy

def check_unauthorized_access(bucket_policy, authorized_accounts):   ->  This logic exists in the send_alert() function
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



I keep getting this error when the lambda is triggered :

[ERROR] TypeError: string indices must be integers, not 'str'
Traceback (most recent call last):
  File "/var/task/s3_policy.py", line 24, in lambda_handler
    functions.send_alert(event, account_alias, message)
  File "/var/task/functions.py", line 36, in send_alert
    for statement in parsed_data["Statement"]:


this is my stack for the lambda function:

from aws_cdk import (
    Stack,
    aws_events as event,
    aws_logs as log,
    aws_lambda as _lambda,
    aws_events_targets as target,
    aws_sns as sns,
    aws_iam as iam,
    aws_kms as kms,
    aws_sns_subscriptions as subscription,
    Duration,
    Tags
)

from constructs import Construct
from emc_cdk import (
    emc_lambda
)

class CdkIAMTrustStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, stack_params: dict, tags: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        sns_topic = sns.Topic(self, "MySNSTopic", display_name="Unauthorized Account Notification", topic_name="Unauthorized_Account_Notification")
        sns_topic.add_subscription(subscription.EmailSubscription(tags["email"]))

        s3_policy_function = emc_lambda.Function(self,
            "S3PolicyLambdaFuntion",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="s3_policy.lambda_handler",
            function_name="s3-bucket-policy",
            code_location='lambda_code',
            tracing=_lambda.Tracing.ACTIVE,
            log_group=log.LogGroup(self, "S3PolicyLambdaLogGroup",
                retention=log.RetentionDays.ONE_MONTH
            ),
            timeout=Duration.seconds(60)
        )

        s3_policy_function.add_to_role_policy(           ->  Instead of redefining the policy statements that we want to add to each lambda multiple times, we can build a managed policy and then attach it to the lambdas by calling iam_function.role.add_managed_policy
That should clean up a lot of this duplicate code
            iam.PolicyStatement(
                actions=[
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds"
                ],
                resources=["arn:aws:secretsmanager:us-east-1:107872598712:secret:account_policy_lambda-GH2Jwz"],
            )
        )

        s3_policy_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "kms:Decrypt"
                ],
                resources=["arn:aws:kms:us-east-1:107872598712:key/2e7acbc5-140b-4dbe-804e-3743fa73c021"]
            )
        )
        # Add permissions to the Lambda function
        s3_policy_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "sns:Publish"
                ],
                resources=[sns_topic.topic_arn],
            )
        )

        s3_policy_function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter"
                ],
                resources=["*"]
            )
        )

        # Create the CloudWatch Events rule
        s3_event_rule = event.Rule(
            self,
            "S3EventRule",
            event_pattern= event.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventName": ["PutBucketPolicy", "DeleteBucketPolicy"],
                }
                
            )

        )

        # Add the Lambda function as the target for the rule
        s3_event_rule.add_target(target.LambdaFunction(s3_policy_function))    - >  Lets add the target when we initialize the object, there isn't a reason we need to do it seperately.





please resolve all the comments "->" anything after that is a comment. also resolve the error for str above.
