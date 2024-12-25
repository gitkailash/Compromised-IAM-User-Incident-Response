# AWS GuardDuty Incident Response with Lambda, EventBridge, and SNS

This project provides an automated solution for responding to **AWS GuardDuty Findings** using **EventBridge**, **AWS Lambda**, and **SNS**. The solution handles anomalous IAM user activities by deactivating MFA devices, disabling login profiles, deleting access keys, and notifying the security team.

---

## Introduction

**Problem Statement**: Unauthorized or anomalous activities by IAM users pose a security threat.

**Solution**: Automate detection and remediation using GuardDuty findings to:
- Deactivate MFA devices
- Disable IAM login profiles
- Delete access keys
- Notify the security team

---

## Architecture

### High-Level Diagram
```plaintext
+-----------------+     +----------------+     +----------------+     +------------------+
| AWS GuardDuty   | --> | EventBridge    | --> | Lambda Function | --> | SNS Notification |
+-----------------+     +----------------+     +----------------+     +------------------+
```
1. GuardDuty detects suspicious IAM user behavior.
2. EventBridge routes findings to the Lambda function.
3. Lambda performs the remediation actions.
4. SNS notifies the security team.

---

## Prerequisites

1. **AWS Account**: Ensure you have access to an AWS account.
2. **IAM Role for Lambda**: Create an IAM role with the necessary permissions.
3. **SNS Topic**: Set up an SNS topic to send notifications.
4. **GuardDuty Enabled**: Activate GuardDuty in your AWS account.

---

## Deployment Steps

### 1. Create IAM Role for Lambda
Attach the following permissions to the IAM role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/IncidentResponse:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "guardduty:ListFindings",
                "guardduty:GetFindings"
            ],
            "Resource": "arn:aws:guardduty:us-east-1:123456789012:detector/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:UpdateUser",
                "iam:ListUsers",
                "iam:ListMFADevices",
                "iam:DeactivateMFADevice",
                "iam:ListAccessKeys",
                "iam:DeleteAccessKey",
                "iam:UpdateLoginProfile"
            ],
            "Resource": "arn:aws:iam::123456789012:user/*"
        },
        {
            "Effect": "Allow",
            "Action": "sns:Publish",
            "Resource": "arn:aws:sns:us-east-1:123456789012:IncidentResponseNotifications"
        }
    ]
}
```

### 2. Deploy Lambda Function
1. Write the Lambda function code to handle:
   - Fetching and deactivating MFA devices
   - Disabling login profiles
   - Deleting access keys
   - Sending SNS notifications
2. Use the AWS Management Console or CLI to deploy the function.

### 3. Create SNS Topic
1. Create an SNS topic.
2. Subscribe the security team's email or phone number.

### 4. Configure EventBridge
Set up the following EventBridge rule:

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "type": [
      "CredentialAccess:IAMUser/AnomalousBehavior",
      "DefenseEvasion:IAMUser/AnomalousBehavior",
      "Discovery:IAMUser/AnomalousBehavior",
      "Exfiltration:IAMUser/AnomalousBehavior",
      "Impact:IAMUser/AnomalousBehavior",
      "InitialAccess:IAMUser/AnomalousBehavior",
      "PenTest:IAMUser/KaliLinux",
      "PenTest:IAMUser/ParrotLinux",
      "PenTest:IAMUser/PentooLinux",
      "Persistence:IAMUser/AnomalousBehavior",
      "Policy:IAMUser/RootCredentialUsage",
      "PrivilegeEscalation:IAMUser/AnomalousBehavior",
      "Recon:IAMUser/MaliciousIPCaller",
      "Recon:IAMUser/MaliciousIPCaller.Custom",
      "Recon:IAMUser/TorIPCaller",
      "Stealth:IAMUser/CloudTrailLoggingDisabled",
      "Stealth:IAMUser/PasswordPolicyChange",
      "UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B",
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS",
      "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
      "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
      "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
      "UnauthorizedAccess:IAMUser/TorIPCaller"
    ]
  }
}
```

---

## CloudWatch Logs
Example log output after Lambda execution:

```
[Info]: Finding Type: Recon: IAMUser/MaliciousIPCaller
[Info]: IAM User: TestUser
[Info]: Fetching MFA devices for user: TestUser
[Info]: Deactivating MFA device: arn:aws:iam::123456789012:mfa/TestUserMFA
[Info]: Disabling login profile for user: TestUser
[Info]: Deleting access key: AKIA1234567890EXAMPLE
[Info]: Sending SNS notification.
[Info]: SNS notification sent successfully.
[Info]: Incident response completed.
```

---

## SNS Notification Format
Example SNS message sent to the security team:

```
GuardDuty Incident Response Completed:
Finding Type: Recon: IAMUser/MaliciousIPCaller
Region: us-east-1
User Type: IAMUser
Resource Type: AccessKey
IAM User: TestUser
MFA Status: MFA devices deactivated
Access Keys Deleted: 2
```

---

## Testing the Setup

1. **Simulate GuardDuty Finding**:
   - Use the GuardDuty console or CLI to simulate a finding.
2. **Trigger EventBridge Rule**:
   - Verify that the finding triggers the Lambda function.
3. **Monitor CloudWatch Logs**:
   - Check logs to confirm actions.
4. **Check SNS Notifications**:
   - Ensure the security team receives the notification.

---

## Conclusion

This solution automates the remediation of IAM user anomalies, improving security and reducing manual effort. The modular architecture ensures easy scalability and integration with additional services.

---

## Notes  

⚠️ **Important Reminder**:  
"Because we all love the thrill of an unexpected AWS bill, don't forget to *not* delete your created services after testing. Who doesn't enjoy explaining a hefty cloud bill to their manager? But hey, if you're into that sort of thing, go ahead and leave it running. 😉" 

---

## License
This project is licensed under the MIT License.

