package org.example.handler;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

class IncidentResponseHandlerTest {
    
    private AmazonIdentityManagement iamClient;
    private IncidentResponseHandler handler;
    private Context context;
    private LambdaLogger logger;
    
    @BeforeEach
    void setUp() {
        iamClient = mock(AmazonIdentityManagement.class);
        context = mock(Context.class);
        logger = mock(LambdaLogger.class);
        when(context.getLogger()).thenReturn(logger);
        
        handler = new IncidentResponseHandler();
    }
    
    @Test
    void testValidUserSuccess() {
        Map<String, Object> event = createEvent("OptsUser");
        
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenReturn(new ListAccessKeysResult());
        
        when(iamClient.listMFADevices(any(ListMFADevicesRequest.class)))
                .thenReturn(new ListMFADevicesResult());
        
        String result = handler.handleRequest(event, context);
        
        verify(logger).log("[Info]: Finding Type: Discovery: IAMUser/AnomalousBehavior");
        verify(logger).log("[Info]: IAM User: OptsUser");
        verify(logger).log("[Info]: Fetching MFA devices for user: OptsUser");
        verify(logger).log("[Info]: Disabling login profile for user: OptsUser");
        verify(logger).log("[Info]: Listing access keys for user: OptsUser");
        verify(logger).log("[Info]: No access keys found for user: OptsUser");
        verify(logger).log("[Info]: Sending SNS notification.");
        verify(logger).log("[Info]: SNS notification sent successfully.");
        verify(logger).log("[Info]: Incident response completed.");
        assert(result.equals("Incident response completed"));
    }
    
    @Test
    void testNoUsername() {
        Map<String, Object> event = createEvent("");
        
        String result = handler.handleRequest(event, context);
        
        verify(logger).log("[Error]: No username provided in the event.");
        assert(result.equals("Failed: No username provided."));
    }
    
    @Test
    void testNoMfaDevice() {
        Map<String, Object> event = createEvent("OptsUser");
        
        when(iamClient.listMFADevices(any(ListMFADevicesRequest.class)))
                .thenReturn(new ListMFADevicesResult());
        
        String result = handler.handleRequest(event, context);
        
        verify(logger).log("[Info]: No MFA devices found for user: OptsUser");
        
        assert(result.equals("Incident response completed"));
    }
    
    @Test
    void testIamExceptionHandling() {
        Map<String, Object> event = createEvent("OptsUser");
        
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenThrow(new AmazonServiceException("Service failure"));
        
        String result = handler.handleRequest(event, context);
        
        verify(logger).log("[ERROR] Failed to disable user: Service failure");
        assert(result.equals("Failed: AWS Service Error: Service failure"));
    }
    
    @Test
    void testSnsNotification() {
        Map<String, Object> event = createEvent("OptsUser");
        
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenReturn(new ListAccessKeysResult());
        
        when(iamClient.listMFADevices(any(ListMFADevicesRequest.class)))
                .thenReturn(new ListMFADevicesResult());
        
        String result = handler.handleRequest(event, context);
        
        verify(logger).log("[Info]: Listing access keys for user: OptsUser");
        verify(logger).log("[Info]: No access keys found for user: OptsUser");
        verify(logger).log("[Info]: Sending SNS notification.");
        verify(logger).log("[Info]: SNS notification sent successfully.");
        verify(logger).log("[Info]: Incident response completed.");
        assert(result.equals("Incident response completed"));
        
    }
    
    @Test
    void testNoAccessKeys() {
        Map<String, Object> event = createEvent("OptsUser");
        
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenReturn(new ListAccessKeysResult());
        
        String result = handler.handleRequest(event, context);
        
        // Assert: Verify logs and result
        verify(logger).log("[Info]: No access keys found for user: OptsUser");
        verify(logger).log("[Info]: Disabling login profile for user: OptsUser");
        verify(logger).log("[Info]: Incident response completed");
        
        assert(result.equals("Incident response completed"));
    }
    
    private Map<String, Object> createEvent(String username) {
        Map<String, Object> event = new HashMap<>();
        Map<String, Object> detail = new HashMap<>();
        detail.put("accountId", "2392755251");
        detail.put("region", "us-east-1");
        detail.put("type", "Discovery: IAMUser/AnomalousBehavior");
        
        Map<String, Object> resource = new HashMap<>();
        resource.put("resourceType", "AccessKey");
        Map<String, Object> accessKeyDetails = new HashMap<>();
        accessKeyDetails.put("userName", username);
        accessKeyDetails.put("userType", "IAMUser");
        resource.put("accessKeyDetails", accessKeyDetails);
        
        detail.put("resource", resource);
        event.put("detail", detail);
        return event;
    }
}
