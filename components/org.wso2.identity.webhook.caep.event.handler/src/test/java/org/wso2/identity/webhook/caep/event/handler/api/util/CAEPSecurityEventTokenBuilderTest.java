package org.wso2.identity.webhook.caep.event.handler.api.util;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertTrue;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.mockServiceURLBuilder;

public class CAEPSecurityEventTokenBuilderTest {

    private static final Logger log = LoggerFactory.getLogger(CAEPSecurityEventTokenBuilderTest.class);
    @Mock
    private EventPayload eventPayload;
    @Mock
    private EventData eventData;
    @InjectMocks
    private CAEPSecurityEventTokenBuilder caepSecurityEventTokenBuilder;

    @BeforeClass
    public void setUp() {

        MockitoAnnotations.openMocks(this);
        mockServiceURLBuilder();
        mockIdentityTenantUtil();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    private EventData getVerificationEventData() {

        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(Constants.EventDataProperties.STREAM_ID, "stream-id");
        return new EventData.Builder()
                .eventName(IdentityEventConstants.EventName.VERIFICATION.name())
                .eventParams(eventParams)
                .build();

    }

    private EventData getSessionCreateEventData() {
        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(Constants.EventDataProperties.SESSION_ID, "session-id");
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        try {
            when(authenticatedUser.getUserId()).thenReturn("user-id");
        } catch (UserIdNotFoundException e) {
            log.error("User ID not found for the authenticated user.");
        }
        when(authenticatedUser.getTenantDomain()).thenReturn("tenant-domain");
        eventParams.put(Constants.EventDataProperties.USER, authenticatedUser);
        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        when(authenticationContext.getSessionIdentifier()).thenReturn("session-id");
        return new EventData.Builder()
                .eventName(IdentityEventConstants.EventName.SESSION_CREATE.name())
                .eventParams(eventParams)
                .authenticatedUser(authenticatedUser)
                .authenticationContext(authenticationContext)
                .build();
    }

    private EventData setUserSessionTerminateEventData() {

        Map<String, Object> eventParams = new HashMap<>();
        List<UserSession> userSessions = Collections.singletonList(mock(UserSession.class));
        eventParams.put(Constants.EventDataProperties.SESSIONS, userSessions);
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        try {
            when(authenticatedUser.getUserId()).thenReturn("user-id");
        } catch (UserIdNotFoundException e) {
            log.error("User ID not found for the authenticated user.");
        }
        when(authenticatedUser.getTenantDomain()).thenReturn("tenant-domain");
        eventParams.put(Constants.EventDataProperties.USER, authenticatedUser);
        return new EventData.Builder()
                .eventName(IdentityEventConstants.EventName.USER_SESSION_TERMINATE.name())
                .eventParams(eventParams)
                .authenticatedUser(authenticatedUser)
                .build();
    }


    @DataProvider(name = "successDataProvider")
    public Object[][] successDataProvider() {
        return new Object[][]{
                {eventPayload, "http://example.com/event", getVerificationEventData()},
                {eventPayload, "http://example.com/event", getSessionCreateEventData()},
                {eventPayload, "http://example.com/event", setUserSessionTerminateEventData()}
        };
    }

    @DataProvider(name = "failureDataProvider")
    public Object[][] failureDataProvider() {
        return new Object[][]{
                {null, "http://example.com/event", eventData},
                {eventPayload, null, eventData},
                {eventPayload, "", eventData},
                {eventPayload, "http://example.com/event", null}
        };
    }

    @Test(dataProvider = "successDataProvider")
    public void testBuildSecurityEventTokenPayloadSuccess(
            EventPayload eventPayload, String eventUri, EventData eventData) throws IdentityEventException {
        SecurityEventTokenPayload securityEventTokenPayload =
                caepSecurityEventTokenBuilder.buildSecurityEventTokenPayload(eventPayload, eventUri, eventData);

        assertNotNull(securityEventTokenPayload);
        assertTrue(securityEventTokenPayload.getEvents().containsKey(eventUri));
        assertEquals(securityEventTokenPayload.getEvents().get(eventUri), eventPayload);
    }

    @Test(dataProvider = "failureDataProvider", expectedExceptions = IdentityEventException.class)
    public void testBuildSecurityEventTokenPayloadFailure(
            EventPayload eventPayload, String eventUri, EventData eventData) throws IdentityEventException {

        caepSecurityEventTokenBuilder.buildSecurityEventTokenPayload(eventPayload, eventUri, eventData);
    }

    @Test
    public void testGetEventSchema() {

        assertEquals(EventSchema.CAEP, caepSecurityEventTokenBuilder.getEventSchema());
    }
}
