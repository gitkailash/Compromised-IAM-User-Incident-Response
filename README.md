# AWS GuardDuty Incident Response with Lambda, EventBridge, and SNS

This project provides an automated solution for responding to **AWS GuardDuty Findings** using **EventBridge**, **AWS Lambda**, **SNS**, and **CloudWatch Alarms**. The solution handles anomalous IAM user activities by deactivating MFA devices, disabling login profiles, deleting access keys, and notifying the security team.

---

## Introduction

**Problem Statement**: Unauthorized or anomalous activities by IAM users pose a security threat.

**Solution**: Automate detection and remediation using GuardDuty findings to:
- Deactivate MFA devices
- Disable IAM login profiles
- Delete access keys
- Notify the security team

---

## Architecture Diagram

<img src="https://github.com/gitkailash/Compromised-IAM-User-Incident-Response/blob/master/src/main/java/resources/GuardDuty-architecture.png" alt="Architecture Diagram"/>

---
1. **GuardDuty**: Detects suspicious IAM user behavior.
2. **EventBridge**: Routes GuardDuty findings to the Lambda function.
3. **Lambda Function**:
   - Performs remediation actions, such as deactivating MFA devices, disabling login profiles, and deleting access keys.
   - Publishes error metrics to **CloudWatch**.
4. **CloudWatch Alarm**: Monitors Lambda error metrics (e.g., `Errors`, `Throttles`).
5. **SNS**: Sends notifications to the security team about remediation and alarms.
---

## Prerequisites

1. **AWS Account**: Ensure you have access to an AWS account.
2. **IAM Role for Lambda**: Create an IAM role with the necessary permissions to:
   - Read from EventBridge.
   - Perform IAM actions (deactivate MFA, delete access keys, etc.).
   - Write metrics to CloudWatch.
   - Publish messages to SNS.
3. **SNS Topic**: Set up an SNS topic to send notifications to the security team.
4. **GuardDuty Enabled**: Activate GuardDuty in your AWS account.
5. **CloudWatch Alarms**: Configure alarms for monitoring Lambda errors.
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
## Sample JSON for Testing Lambda
```json
{
  "detail": {
    "schemaVersion": "2.0",
    "accountId": "123456789012",
    "region": "us-east-1",
    "partition": "aws",
    "id": "abc1234567890def1234567890abcdef",
    "arn": "arn:aws:guardduty:us-east-1:123456789012:detector/xyz9876543210fedcba0987654321/deabc1234567890def1234567890abcdef",
    "type": "Recon: IAMUser/MaliciousIPCaller",
    "resource": {
      "resourceType": "AccessKey",
      "accessKeyDetails": {
        "accessKeyId": "AKIAEXAM5LEACCESSKEY",
        "principalId": "AIDABC3EFGHIJKLMNO",
        "userType": "IAMUser",
        "userName": "TestUserName"
      }
    }
  }
}
```
---

## Sample AWS CLI (Optional)
This step is optional.

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text --region us-east-1)

aws guardduty create-sample-findings --detector-id $DETECTOR_ID --finding-types "Recon:IAMUser/MaliciousIPCaller"

aws guardduty create-sample-findings --detector-id $DETECTOR_ID --finding-types "CredentialAccess:IAMUser/AnomalousBehavior"

aws guardduty create-sample-findings --detector-id $DETECTOR_ID --finding-types "Discovery:IAMUser/AnomalousBehavior"
```
---

## CloudWatch Logs
Log Groups output after Lambda execution:
![Log Groups Output](src/main/java/resources/log-group.PNG)  

---

## SNS Notification Format
SNS Notification sent to the security team:
![Log Groups Output](src/main/java/resources/SNS-mail.PNG)  

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

