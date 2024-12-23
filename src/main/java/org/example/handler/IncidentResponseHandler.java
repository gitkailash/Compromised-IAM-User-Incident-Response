package org.example.handler;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.*;

import java.util.Map;

public class IncidentResponseHandler implements RequestHandler<Map<String, String>, String> {
    
    private AmazonIdentityManagement iamClient;
    
    // Default constructor uses the default client from AWS SDK
    public IncidentResponseHandler() {
        this.iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
    }
    
    // Setter method to inject IAM client (used in tests)
    public void setIamClient(AmazonIdentityManagement iamClient) {
        this.iamClient = iamClient;
    }
    
    public String handleRequest(Map<String, String> event, Context context) {
        LambdaLogger logger = context.getLogger();
        String userName = event.get("username");
        
        if (userName == null || userName.isEmpty()) {
            logger.log("[ERROR] No username provided in the event.");
            return "Failed: No username provided.";
        }
        
        logger.log("[INFO] Starting incident response for user: " + userName);
        
        iamClient = AmazonIdentityManagementClientBuilder.defaultClient();
        
        try {
            // Fetch MFA devices for the user
            ListMFADevicesRequest listMFADevicesRequest = new ListMFADevicesRequest().withUserName(userName);
            ListMFADevicesResult mfaDevicesResult = iamClient.listMFADevices(listMFADevicesRequest);
            
            if (mfaDevicesResult.getMFADevices().isEmpty()) {
                logger.log("[INFO] No MFA devices found for user: " + userName);
            } else {
                // Deactivate the first MFA device
                MFADevice mfaDevice = mfaDevicesResult.getMFADevices().get(0);
                String serialNumber = mfaDevice.getSerialNumber();
                logger.log("[INFO] Deactivating MFA device with serial number: " + serialNumber);
                iamClient.deactivateMFADevice(new DeactivateMFADeviceRequest()
                        .withUserName(userName)
                        .withSerialNumber(serialNumber));
                logger.log("[INFO] MFA devices deactivated for user: " + userName);
            }
            
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
        } catch (NoSuchEntityException e) {
            logger.log("[ERROR] User " + userName + " does not exist.");
            return "Failed: User " + userName + " does not exist.";
        } catch (AmazonServiceException e) {
            logger.log("[ERROR] AWS service exception occurred: " + e.getMessage());
            return "Failed: AWS Service Error: " + e.getMessage();
        } catch (Exception e) {
            logger.log("[ERROR] An unexpected error occurred: " + e.getMessage());
            return "Failed: Unexpected error: " + e.getMessage();
        }
    }
}
