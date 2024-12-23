package org.example.handler;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.model.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.*;

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
        handler.setIamClient(iamClient);
    }
    
    @Test
    void testValidUserSuccess() {
        // Prepare a valid event
        Map<String, String> event = new HashMap<>();
        event.put("username", "OptsUser");
        
        // Mock the IAM client responses
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenReturn(new ListAccessKeysResult()); // Mock empty response for keys
        
        // Mock no MFA devices
        when(iamClient.listMFADevices(any(ListMFADevicesRequest.class)))
                .thenReturn(new ListMFADevicesResult());
        
        // Call the Lambda handler
        String result = handler.handleRequest(event, context);
        
        // Validate the result
        verify(logger).log("[INFO] Starting incident response for user: OptsUser");
        verify(logger).log("[SUCCESS] MFA devices deactivated for user: OptsUser");
        verify(logger).log("[SUCCESS] Login profile disabled for user: OptsUser");
        verify(logger).log("[SUCCESS] All access keys deleted for user: OptsUser");
        assert(result.equals("Success: User OptsUser disabled."));
    }
    
    @Test
    void testNoUsername() {
        // Prepare event with no username
        Map<String, String> event = new HashMap<>();
        event.put("username", "");
        
        // Call the Lambda handler
        String result = handler.handleRequest(event, context);
        
        // Validate the result
        verify(logger).log("[ERROR] No username provided in the event.");
        assert(result.equals("Failed: No username provided."));
    }
    
    @Test
    void testInvalidUser() {
        // Prepare event with null username
        Map<String, String> event = new HashMap<>();
        event.put("username", null);
        
        // Call the Lambda handler
        String result = handler.handleRequest(event, context);
        
        // Validate the result
        verify(logger).log("[ERROR] No username provided in the event.");
        assert(result.equals("Failed: No username provided."));
    }
    
    @Test
    void testNoMfaDevice() {
        // Prepare event with a valid username
        Map<String, String> event = new HashMap<>();
        event.put("username", "OptsUser");
        
        // Mock the IAM client responses
        when(iamClient.listMFADevices(any(ListMFADevicesRequest.class)))
                .thenReturn(new ListMFADevicesResult()); // No MFA devices
        
        // Call the Lambda handler
        String result = handler.handleRequest(event, context);
        
        // Validate that the error is logged, but the process continues
        verify(logger).log("[INFO] Starting incident response for user: OptsUser");
        verify(logger).log("[INFO] Attempting to deactivate MFA devices for user: OptsUser");
        verify(logger).log("[SUCCESS] MFA devices deactivated for user: OptsUser");
        assert(result.equals("Success: User OptsUser disabled."));
    }
    
    @Test
    void testNoAccessKeys() {
        // Prepare event with a valid username
        Map<String, String> event = new HashMap<>();
        event.put("username", "OptsUser");
        
        // Mock the IAM client responses (no access keys)
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenReturn(new ListAccessKeysResult()); // No access keys for the user
        
        // Call the Lambda handler
        String result = handler.handleRequest(event, context);
        
        // Validate that the log is present but the process continues
        verify(logger).log("[INFO] Starting incident response for user: OptsUser");
        verify(logger).log("[INFO] Fetching access keys for user: OptsUser");
        verify(logger).log("[SUCCESS] All access keys deleted for user: OptsUser");
        assert(result.equals("Success: User OptsUser disabled."));
    }
    
    @Test
    void testIamExceptionHandling() {
        // Prepare event with a valid username
        Map<String, String> event = new HashMap<>();
        event.put("username", "OptsUser");
        
        // Simulate an IAM failure (e.g., service exception)
        when(iamClient.listAccessKeys(any(ListAccessKeysRequest.class)))
                .thenThrow(new AmazonServiceException("Service failure"));
        
        // Call the Lambda handler
        String result = handler.handleRequest(event, context);
        
        // Validate the result
        verify(logger).log("[ERROR] Failed to disable user: Service failure");
        assert(result.equals("Failed: AWS Service Error: Service failure"));
    }
}
