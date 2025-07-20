/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.common.event.handler.internal.util;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.slf4j.MDC;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.common.ComplexSubject;
import org.wso2.carbon.identity.event.publisher.api.model.common.SimpleSubject;
import org.wso2.carbon.identity.event.publisher.api.model.common.Subject;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.util.TestUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;

/**
 * Test class for EventHookHandlerUtils.
 */
public class EventHookHandlerUtilsTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_TENANT_ID = "100";

    @Mock
    private AuthenticationContext mockedAuthenticationContext;

    @Mock
    private AuthenticatedUser mockedAuthenticatedUser;

    @Mock
    private EventPublisherService mockedEventPublisherService;

    @BeforeMethod
    public void setup() throws Exception {

        MockitoAnnotations.openMocks(this);
        CommonTestUtils.initPrivilegedCarbonContext();
    }
       //TODO Uncomment the below test once the MDC is set in the EventHookHandlerUtils class.
//    /**
//     * Test for correlation ID generation.
//     */
//    @Test
//    public void testGetCorrelationID() {
//
//        String correlationID = EventHookHandlerUtils.getCorrelationID();
//        assertNotNull(correlationID, "Correlation ID should not be null");
//        // Test if correlation ID is a valid UUID format
//        assertTrue(correlationID.matches(
//                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
//    }

    @Test
    public void testConstructBaseURL() {

        TestUtils.mockServiceURLBuilder();
        String baseURL = EventHookHandlerUtils.constructBaseURL();
        assertEquals(baseURL, "https://localhost:9443", "Base URL should be correctly constructed.");
        closeMockedServiceURLBuilder();
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildSecurityEventTokenWithNullEventPayload() throws IdentityEventException {

        EventHookHandlerUtils.buildSecurityEventToken(null, "eventUri");
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildSecurityEventTokenWithNullEventURI() throws IdentityEventException {

        EventPayload payload = mock(EventPayload.class);
        EventHookHandlerUtils.buildSecurityEventToken(payload, null);
    }

    @Test
    public void testConstructBaseURLSuccess() {

        TestUtils.mockServiceURLBuilder();
        String baseURL = EventHookHandlerUtils.constructBaseURL();
        assertNotNull(baseURL, "Base URL should not be null");
        closeMockedServiceURLBuilder();
    }

    @Test
    public void testBuildEventDataProviderSuccess() throws IdentityEventException {

        Map<String, Object> properties = new HashMap<>();
        Map<String, Object> eventParams = new HashMap<>();
        eventParams.put(Constants.EventDataProperties.USER, mockedAuthenticatedUser);
        eventParams.put(Constants.EventDataProperties.EVENT_TIMESTAMP, System.currentTimeMillis());
        eventParams.put(Constants.EventDataProperties.SESSION_DATA, "SessionData");
        eventParams.put(Constants.EventDataProperties.SESSION_ID, "SessionID");
        eventParams.put(Constants.EventDataProperties.STATE, "State");
        eventParams.put(Constants.EventDataProperties.STREAM_ID, "StreamID");
        eventParams.put(Constants.EventDataProperties.REQUEST, mock(HttpServletRequest.class));
        properties.put(Constants.EventDataProperties.CONTEXT, mockedAuthenticationContext);
        properties.put(Constants.EventDataProperties.PARAMS, eventParams);
        properties.put(Constants.EventDataProperties.SESSION_CONTEXT, mock(SessionContext.class));
        Event event = new Event(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name(), properties);

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        assertNotNull(eventData, "EventData should not be null");
        assertEquals(eventData.getEventName(), IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name(),
                "Event name should match");
        assertEquals(eventData.getEventName(), IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name(),
                "Event name should match");
        assertEquals(eventData.getAuthenticatedUser(), mockedAuthenticatedUser,
                "Authenticated user should match");
        assertEquals(eventData.getAuthenticationContext(), mockedAuthenticationContext,
                "Authentication context should match");
        assertNotNull(eventData.getSessionContext(), "Session context should not be null");
        assertEquals(eventData.getEventParams().get(Constants.EventDataProperties.USER), mockedAuthenticatedUser,
                "Event parameter 'USER' should match");
        assertNotNull(eventData.getEventParams().get(Constants.EventDataProperties.EVENT_TIMESTAMP),
                "Event parameter 'EVENT_TIMESTAMP' should not be null");
        assertEquals(eventData.getEventParams().get(Constants.EventDataProperties.SESSION_DATA), "SessionData",
                "Event parameter 'SESSION_DATA' should match");
        assertEquals(eventData.getEventParams().get(Constants.EventDataProperties.SESSION_ID), "SessionID",
                "Event parameter 'SESSION_ID' should match");
        assertEquals(eventData.getEventParams().get(Constants.EventDataProperties.STATE), "State",
                "Event parameter 'STATE' should match");
        assertEquals(eventData.getEventParams().get(Constants.EventDataProperties.STREAM_ID), "StreamID",
                "Event parameter 'STREAM_ID' should match");
        assertNotNull(eventData.getEventParams().get(Constants.EventDataProperties.REQUEST),
                "Event parameter 'REQUEST' should not be null");

    }

    @Test
    public void testGetCorrelationIDWithExistingCorrelationID() {

        String expectedCorrelationID = "test-correlation-id";
        try (MockedStatic<MDC> mockedMDC = mockStatic(MDC.class)) {
            mockedMDC.when(() -> MDC.get("Correlation-ID")).thenReturn(expectedCorrelationID);

            String correlationID = EventHookHandlerUtils.getCorrelationID();

            assertNotNull(correlationID, "Correlation ID should not be null");
            assertEquals(correlationID, expectedCorrelationID, "Correlation ID should match the expected value");

            mockedMDC.verify(() -> MDC.put("Correlation-ID", expectedCorrelationID), times(0));
        }
    }
      //TODO Uncomment the below tests once the MDC is set in the EventHookHandlerUtils class.
//    @Test
//    public void testGetCorrelationIDWithoutExistingCorrelationID() {
//
//        MDC.clear();
//        String correlationID = EventHookHandlerUtils.getCorrelationID();
//        assertNotNull(correlationID, "A new correlation ID should be generated");
//    }
//
//    @Test
//    public void testGetCorrelationIDWhenMDCNotSet() {
//
//        MDC.clear();
//        String correlationID = EventHookHandlerUtils.getCorrelationID();
//        assertNotNull(correlationID);
//        assertTrue(correlationID.matches(
//                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
//    }

    @DataProvider(name = "extractSubjectDataProvider")
    public Object[][] extractSubjectDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.EventName.SESSION_CREATE.name()},
        };
    }

    @Test(dataProvider = "extractSubjectDataProvider")
    public void testExtractSubjectFromEventData(String eventName) throws
            IdentityEventException, UserIdNotFoundException {

        EventData eventData = mock(EventData.class);

        when(eventData.getAuthenticatedUser()).thenReturn(mockedAuthenticatedUser);
        when(mockedAuthenticatedUser.getUserId()).thenReturn("user-id-123");
        when(mockedAuthenticatedUser.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);

        when(eventData.getAuthenticationContext()).thenReturn(mockedAuthenticationContext);
        when(mockedAuthenticationContext.getSessionIdentifier()).thenReturn("session-id-123");
        mockIdentityTenantUtil();

        when(eventData.getEventName()).thenReturn(eventName);

        Subject subject = EventHookHandlerUtils.extractSubjectFromEventData(eventData);

        closeMockedIdentityTenantUtil();

        assertNotNull(subject, "Subject should not be null");
        assertTrue(subject instanceof ComplexSubject, "Subject should be of type ComplexSubject");

        ComplexSubject complexSubject = (ComplexSubject) subject;
        assertEquals(complexSubject.getProperties().size(), 3, "ComplexSubject should contain 3 subjects");
        complexSubject.getProperties().forEach((key, value) -> {
            assertTrue(value instanceof SimpleSubject, "Value should be of type SimpleSubject");
            SimpleSubject simpleSubject = (SimpleSubject) value;
            if (key.equals("user")) {
                assertEquals(simpleSubject.getProperty("id"), "user-id-123", "User ID should match");
            } else if (key.equals("tenant")) {
                assertEquals(simpleSubject.getProperty("id"), SAMPLE_TENANT_ID, "Tenant domain should match");
            } else if (key.equals("session")) {
                assertEquals(simpleSubject.getProperty("id"), "session-id-123", "Session ID should match");
            }
        });
    }

    @Test
    public void testBuildVerificationSubject() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("streamId", "stream-id-123");
        when(eventData.getEventParams()).thenReturn(Collections.unmodifiableMap(dataMap));

        Subject subject = EventHookHandlerUtils.buildVerificationSubject(eventData);

        assertNotNull(subject, "Subject should not be null");
        assertTrue(subject instanceof SimpleSubject, "Subject should be of type SimpleSubject");
        assertEquals(subject.getProperty("id"), "stream-id-123", "Stream ID should match");
    }
}
