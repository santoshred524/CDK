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
