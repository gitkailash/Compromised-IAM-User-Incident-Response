package org.example.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.*;

import java.util.Map;

public class IncidentResponseHandler implements RequestHandler<Map<String, String>, String> {
    
    public String handleRequest(Map<String, String> event, Context context) {
        LambdaLogger logger = context.getLogger();
        String userName = event.get("username");
        
        if (userName == null || userName.isEmpty()) {
            logger.log("[ERROR] No username provided in the event.");
            return "Failed: No username provided.";
        }
        
        logger.log("[INFO] Starting incident response for user: " + userName);
        
        AmazonIdentityManagement iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        try {
            // Deactivate MFA device
            logger.log("[INFO] Attempting to deactivate MFA devices for user: " + userName);
            iamClient.deactivateMFADevice(new DeactivateMFADeviceRequest().withUserName(userName));
            logger.log("[SUCCESS] MFA devices deactivated for user: " + userName);
            
            // Disable login profile
            logger.log("[INFO] Disabling login profile for user: " + userName);
            iamClient.updateLoginProfile(new UpdateLoginProfileRequest().withUserName(userName).withPasswordResetRequired(true));
            logger.log("[SUCCESS] Login profile disabled for user: " + userName);
            
            // Delete access keys
            logger.log("[INFO] Fetching access keys for user: " + userName);
            for (AccessKeyMetadata key : iamClient.listAccessKeys(new ListAccessKeysRequest().withUserName(userName)).getAccessKeyMetadata()) {
                logger.log("[INFO] Deleting access key: " + key.getAccessKeyId());
                iamClient.deleteAccessKey(new DeleteAccessKeyRequest().withUserName(userName).withAccessKeyId(key.getAccessKeyId()));
            }
            logger.log("[SUCCESS] All access keys deleted for user: " + userName);
            
            logger.log("[INFO] Incident response completed successfully for user: " + userName);
            return "Success: User " + userName + " disabled.";
        } catch (Exception e) {
            logger.log("[ERROR] Failed to disable user: " + e.getMessage());
            return "Failed: " + e.getMessage();
        }
    }
}
