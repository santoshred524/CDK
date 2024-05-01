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

# Create Managed Policy
        managed_policy = iam.ManagedPolicy(self, "ManagedPolicy",
            managed_policy_name="AccountTrustPolicy",
            statements=[
                iam.PolicyStatement(
                actions=[
                    "secretsmanager:GetResourcePolicy",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:ListSecretVersionIds"
                ],
                resources=["arn:aws:secretsmanager:us-east-1:107872598712:secret:account_policy_lambda-GH2Jwz"],
            ),
            iam.PolicyStatement(
                actions=[
                    "kms:Decrypt"
                ],
                resources=["arn:aws:kms:us-east-1:107872598712:key/2e7acbc5-140b-4dbe-804e-3743fa73c021"]
            ),
            iam.PolicyStatement(
                actions=[
                    "sns:Publish"
                ],
                resources=[sns_topic.topic_arn],
            ),
            iam.PolicyStatement(
                actions=[
                    "ssm:GetParameter"
                ],
                resources=["*"]
            )
            ]
        )


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

        s3_policy_function.role.add_managed_policy(managed_policy)

        # Create the CloudWatch Events rule
        event_rule = event.Rule(
            self,
            "S3EventRule",
            event_pattern= event.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventName": ["PutBucketPolicy", "DeleteBucketPolicy"],
                }
                
            ),
            targets=[target.LambdaFunction(s3_policy_function)]
        )







[ERROR]	2024-05-01T19:12:07.310Z	c8f17f34-4a00-492a-9f37-f1ecb675a584	Error: An error occurred (AuthorizationError) when calling the Publish operation: User: arn:aws:sts::310476877601:assumed-role/IAMTrustNotification-S3PolicyLambdaFuntionServiceRo-lEinGFqEZf3w/training10-s3-bucket-policy is not authorized to perform: SNS:Publish on resource: arn:aws:sns:us-east-1:310476877601:IAM_Role_Notifications because no identity-based policy allows the SNS:Publish action
