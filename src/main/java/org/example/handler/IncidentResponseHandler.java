package org.example.handler;

import com.amazonaws.services.identitymanagement.*;
import com.amazonaws.services.identitymanagement.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.sns.AmazonSNS;
import com.amazonaws.services.sns.AmazonSNSClientBuilder;
import com.amazonaws.services.sns.model.PublishRequest;

import java.util.Map;

public class IncidentResponseHandler implements RequestHandler<Map<String, Object>, String> {
    
    private final IAMService iamService;
    private final NotificationService notificationService;
    private static final String NO_ACTION_TAKEN = "No action taken";
    private static final String SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:IncidentResponseNotifications"; //need to change ARN
    
    public IncidentResponseHandler() {
        this.iamService = new IAMService(AmazonIdentityManagementClientBuilder.defaultClient());
        this.notificationService = new NotificationService(AmazonSNSClientBuilder.defaultClient(), SNS_TOPIC_ARN);
    }
    
    public IncidentResponseHandler(IAMService iamService, NotificationService notificationService) {
        this.iamService = iamService;
        this.notificationService = notificationService;
    }
    
    @Override
    public String handleRequest(Map<String, Object> event, Context context) {
        LambdaLogger logger = context.getLogger();
        logger.log("Received event: " + event);
        
        try {
            Map<String, Object> detail = (Map<String, Object>) event.get("detail");
            if (detail == null) {
                logger.log("[Error]: No 'detail' field in the event.");
                return NO_ACTION_TAKEN;
            }
            String region = (String) detail.get("region");
            String findingType = (String) detail.get("type");
            Map<String, Object> resource = (Map<String, Object>) detail.get("resource");
            if (findingType == null || resource == null) {
                logger.log("[Error]: Invalid event structure. Missing 'type' or 'resource'.");
                return NO_ACTION_TAKEN;
            }
            
            String resourceType = (String) resource.get("resourceType");
            if (resourceType == null) {
                logger.log("[Info]: NO 'resourceType' in finding resource");
                return NO_ACTION_TAKEN;
            }
            
            Map<String, Object> accessKeyDetails = (Map<String, Object>) resource.get("accessKeyDetails");
            if (accessKeyDetails == null) {
                logger.log("[Error]: No 'accessKeyDetails' in the finding resource.");
                return NO_ACTION_TAKEN;
            }
            
            String userName = (String) accessKeyDetails.get("userName");
            if (userName == null || userName.isEmpty()) {
                logger.log("[Error]: No username provided in the event.");
                return "Failed: No username provided.";
            }
            
            String userType = (String) accessKeyDetails.get("userType");
            if (userType == null) {
                logger.log("[Info]: NO 'userType' in finding resource");
                return NO_ACTION_TAKEN;
            }
            
            logger.log("[Info]: Finding Type: " + findingType);
            logger.log("[Info]: IAM User: " + userName);
            
            // Perform IAM actions
            IncidentResponseResult responseResult = iamService.handleIncident(userName, logger);
            
            // Check if the response indicates success (e.g., access keys deleted or MFA status updated)
            if (responseResult.getAccessKeysDeleted() > 0 || responseResult.getMfaStatus() != null) {
                notificationService.sendNotification(findingType, region, userType, resourceType, userName, responseResult, logger);
                logger.log("[Info]: Notification sent successfully.");
            } else {
                logger.log("[Info]: Incident handling did not require notification.");
            }
            
            logger.log("[Info]: Incident response completed.");
            return "Incident response completed";
            
        } catch (Exception e) {
            logger.log("Error processing GuardDuty finding: " + e.getMessage());
            return "Error";
        }
    }
}

class IAMService {
    private final AmazonIdentityManagement iamClient;
    
    public IAMService(AmazonIdentityManagement iamClient) {
        this.iamClient = iamClient;
    }
    
    public IncidentResponseResult handleIncident(String userName, LambdaLogger logger) {
        IncidentResponseResult result = new IncidentResponseResult();
        
        // Deactivate MFA
        logger.log("[Info]: Fetching MFA devices for user: " + userName);
        ListMFADevicesResult mfaDevicesResult = iamClient.listMFADevices(new ListMFADevicesRequest().withUserName(userName));
        if (mfaDevicesResult.getMFADevices().isEmpty()) {
            logger.log("[Info]: No MFA devices found for user: " + userName);
            result.setMfaStatus("No MFA devices found");
        } else {
            for (MFADevice mfaDevice : mfaDevicesResult.getMFADevices()) {
                String serialNumber = mfaDevice.getSerialNumber();
                logger.log("[Info]: Deactivating MFA device: " + serialNumber);
                iamClient.deactivateMFADevice(new DeactivateMFADeviceRequest().withUserName(userName).withSerialNumber(serialNumber));
            }
            result.setMfaStatus("MFA devices deactivated");
        }
        
        // Disable login profile
        logger.log("[Info]: Disabling login profile for user: " + userName);
        try {
            iamClient.updateLoginProfile(new UpdateLoginProfileRequest().withUserName(userName).withPasswordResetRequired(true));
        } catch (NoSuchEntityException e) {
            logger.log("[Info]: No login profile found for user: " + userName);
        }
        
        // Delete access keys
        logger.log("[Info]: Listing access keys for user: " + userName);
        ListAccessKeysResult accessKeysResult = iamClient.listAccessKeys(new ListAccessKeysRequest().withUserName(userName));
        if (accessKeysResult.getAccessKeyMetadata().isEmpty()) {
            logger.log("[Info]: No access keys found for user: " + userName);
        } else {
            int keysDeleted = 0;
            for (AccessKeyMetadata key : accessKeysResult.getAccessKeyMetadata()) {
                logger.log("[Info]: Deleting access key: " + key.getAccessKeyId());
                iamClient.deleteAccessKey(new DeleteAccessKeyRequest().withUserName(userName).withAccessKeyId(key.getAccessKeyId()));
                keysDeleted++;
            }
            result.setAccessKeysDeleted(keysDeleted);
        }
        
        return result;
    }
}

class NotificationService {
    private final AmazonSNS snsClient;
    private final String topicArn;
    
    public NotificationService(AmazonSNS snsClient, String topicArn) {
        this.snsClient = snsClient;
        this.topicArn = topicArn;
    }
    
    public void sendNotification(String findingType, String region, String userType, String resourceType, String userName, IncidentResponseResult result, LambdaLogger logger) {
        String message = String.format(
                "GuardDuty Incident Response Completed:\n" +
                        "Finding Type: %s\n" +
                        "Region: %s\n" +
                        "User Type: %s\n" +
                        "Resource Type: %s\n" +
                        "IAM User: %s\n" +
                        "MFA Status: %s\n" +
                        "Access Keys Deleted: %d",
                findingType, region, userType, resourceType, userName, result.getMfaStatus(), result.getAccessKeysDeleted()
        );
        try {
            logger.log("[Info]: Sending SNS notification.");
            snsClient.publish(new PublishRequest().withTopicArn(topicArn).withMessage(message).withSubject("GuardDuty Security Alert"));
            logger.log("[Info]: SNS notification sent successfully.");
        } catch (Exception e) {
            logger.log("[Error]: Failed to send SNS notification: " + e.getMessage());
        }
    }
}

class IncidentResponseResult {
    private String mfaStatus;
    private int accessKeysDeleted;
    
    public String getMfaStatus() {
        return mfaStatus;
    }
    
    public void setMfaStatus(String mfaStatus) {
        this.mfaStatus = mfaStatus;
    }
    
    public int getAccessKeysDeleted() {
        return accessKeysDeleted;
    }
    
    public void setAccessKeysDeleted(int accessKeysDeleted) {
        this.accessKeysDeleted = accessKeysDeleted;
    }
}
