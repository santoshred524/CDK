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













from aws_cdk import (
    Stack,
    aws_events as event,
    aws_logs as log,
    aws_lambda as _lambda,
    aws_events_targets as target,
    aws_sns as sns,
    aws_iam as iam,
    aws_sns_subscriptions as subscription,
    Duration,
    Tags
)

from constructs import Construct
from emc_cdk import (
    emc_lambda,
    emc_s3
)

class Cdks3BucketPolicyStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, stack_params: dict, tags: dict, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        sns_topic = sns.Topic(self, "MySNSTopic", display_name="S3 Bucket Policy Notifications", topic_name="S3_Bucket_Policy_Notifications")
        sns_topic.add_subscription(subscription.EmailSubscription(tags["email"]))

        function = emc_lambda.Function(self,
            "LambdaFuntion",
            runtime=_lambda.Runtime.PYTHON_3_11,
            handler="s3_policy.lambda_handler",
            function_name="s3-bucket-policy",
            code_location='lambda_code',
            tracing=_lambda.Tracing.ACTIVE,
            log_group=log.LogGroup(self, "LambdaLogGroup",
                retention=log.RetentionDays.ONE_MONTH
            ),
            timeout=Duration.seconds(60)
        )

        # Add permissions to the Lambda function
        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "sns:Publish"
                ],
                resources=[sns_topic.topic_arn],
            )
        )

        function.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter"
                ],
                resources=["*"]
            )
        )

        # Create the CloudWatch Events rule
        event_rule = event.Rule(
            self,
            "EventRule",
            event_pattern= event.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventName": ["PutBucketPolicy", "DeleteBucketPolicy"],
                }
                
            )

        )

        # Add the Lambda function as the target for the rule
        event_rule.add_target(target.LambdaFunction(function))
        
        self.app_name = 'ace-test'

        emc_s3.Bucket(
            self,
            'Bucket',
            bucket_name = self.app_name
        )

        yum_bucket.bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions = [
                    's3:GetObject',
                    's3:List*'
                ],
                effect = iam.Effect.ALLOW,
                principals = [
                    iam.AnyPrincipal()
                ],
                resources=[
                    yum_bucket.bucket.bucket_arn,
                    f"{yum_bucket.bucket.bucket_arn}/*"
                ],
                conditions= {
                    "StringEquals":{
                        "aws:PrincipalOrgID": "o-vwlfnq1mo3"
                    }
                }
            )
        )
