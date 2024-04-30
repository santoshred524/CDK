import json
import logging
from functions import get_ssm_parameter, send_alert, get_aws_accounts

def lambda_handler(event, context):
    try:
        # Retrieve Account Alias and Authorized Accounts
        account_alias = get_ssm_parameter("/global/account/alias")
        authorized_accounts = get_aws_accounts()

        # Extract bucket name and bucket policy from the CloudTrail event
        bucket_name, bucket_policy = extract_policy_details(event)

        # Convert bucket policy to a dictionary if it's a string
        if isinstance(bucket_policy, str):
            bucket_policy = json.loads(bucket_policy)

        # Check for unauthorized account access
        unauthorized_found = check_unauthorized_access(bucket_policy, authorized_accounts)

        # Send notification if unauthorized accounts are found
        if unauthorized_found:
            message = (f"Unauthorized account(s) {', '.join(unauthorized_found)} detected in bucket policy "
                       f"of {bucket_name} in account {account_alias}.")
            send_alert(event, bucket_policy, message)
        else:
            logging.info("No unauthorized accounts found in bucket policy.")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        raise

def extract_policy_details(event):
    """Extracts and returns bucket name and policy from the event using direct indexing for mandatory fields."""
    bucket_name = event['detail']['requestParameters']['bucketName']
    bucket_policy = event['detail']['requestParameters']['bucketPolicy']
    return bucket_name, bucket_policy

def check_unauthorized_access(bucket_policy, authorized_accounts):
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




from aws_cdk import (
    Stack,
    aws_events as events,
    aws_logs as logs,
    aws_lambda as lambda_,
    aws_events_targets as targets,
    aws_sns as sns,
    aws_iam as iam,
    aws_kms as kms,
    aws_sns_subscriptions as subscriptions,
    Duration
)
from constructs import Construct

class CdkIAMTrustStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, stack_params: dict, tags: dict, **kwargs):
        super().__init__(scope, construct_id, **kwargs)

        sns_topic = sns.Topic(self, "MySNSTopic",
                              display_name="Unauthorized Account Notification",
                              topic_name="Unauthorized_Account_Notification")
        sns_topic.add_subscription(subscriptions.EmailSubscription(tags["email"]))

        lambda_function = lambda_.Function(self, "S3PolicyLambdaFunction",
                                           runtime=lambda_.Runtime.PYTHON_3_8,
                                           handler="s3_policy.lambda_handler",
                                           function_name="s3-bucket-policy",
                                           code=lambda_.Code.from_asset('path/to/your/code'),
                                           tracing=lambda_.Tracing.ACTIVE,
                                           log_group=logs.LogGroup(self, "S3PolicyLambdaLogGroup",
                                                                   retention=logs.RetentionDays.ONE_MONTH),
                                           timeout=Duration.seconds(60))

        # Policy statements
        policy_statements = [
            iam.PolicyStatement(actions=["secretsmanager:GetResourcePolicy",
                                         "secretsmanager:GetSecretValue",
                                         "secretsmanager:DescribeSecret",
                                         "secretsmanager:ListSecretVersionIds"],
                                resources=["arn:aws:secretsmanager:us-east-1:107872598712:secret:account_policy_lambda-GH2Jwz"]),
            iam.PolicyStatement(actions=["kms:Decrypt"],
                                resources=["arn:aws:kms:us-east-1:107872598712:key/2e7acbc5-140b-4dbe-804e-3743fa73c021"]),
            iam.PolicyStatement(actions=["sns:Publish"],
                                resources=[sns_topic.topic_arn]),
            iam.PolicyStatement(actions=["ssm:GetParameter"],
                                resources=["*"])
        ]
        for statement in policy_statements:
            lambda_function.add_to_role_policy(statement)

        # CloudWatch Events rule
        s3_event_rule = events.Rule(self, "S3EventRule",
                                    event_pattern=events.EventPattern(
                                        source=["aws.s3"],
                                        detail_type=["AWS API Call via CloudTrail"],
                                        detail={"eventName": ["PutBucketPolicy", "DeleteBucketPolicy"]}
                                    ),
                                    targets=[targets.LambdaFunction(lambda_function)]
                                    )

