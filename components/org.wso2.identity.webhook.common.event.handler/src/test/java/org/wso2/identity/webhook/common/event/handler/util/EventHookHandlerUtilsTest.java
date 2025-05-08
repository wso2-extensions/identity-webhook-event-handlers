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

package org.wso2.identity.webhook.common.event.handler.util;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.slf4j.MDC;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.event.common.publisher.model.common.ComplexSubject;
import org.wso2.identity.event.common.publisher.model.common.SimpleSubject;
import org.wso2.identity.event.common.publisher.model.common.Subject;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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
    public void setup() {

        MockitoAnnotations.openMocks(this);
    }

    /**
     * Test for correlation ID generation.
     */
    @Test
    public void testGetCorrelationID() {

        String correlationID = EventHookHandlerUtils.getCorrelationID();
        assertNotNull(correlationID, "Correlation ID should not be null");
        // Test if correlation ID is a valid UUID format
        assertTrue(correlationID.matches(
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
    }

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

        EventPayload payload = Mockito.mock(EventPayload.class);
        EventHookHandlerUtils.buildSecurityEventToken(payload, null);
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testPublishEventPayloadWithNullPayload() throws IdentityEventException {

        SecurityEventTokenPayload nullPayload = null;
        EventHookHandlerUtils.publishEventPayload(nullPayload, "sampleTenant", "sampleEventUri");
        Assert.fail("Expected IdentityEventException was not thrown when payload is null.");
    }

    @Test
    public void testPublishEventPayloadWithProperPayload() throws Exception {

        try (MockedStatic<EventHookHandlerDataHolder> mockedDataHolder =
                     Mockito.mockStatic(EventHookHandlerDataHolder.class)) {

            EventHookHandlerDataHolder mockDataHolderInstance = Mockito.mock(EventHookHandlerDataHolder.class);
            when(EventHookHandlerDataHolder.getInstance()).thenReturn(mockDataHolderInstance);

            when(mockDataHolderInstance.getEventPublisherService()).thenReturn(mockedEventPublisherService);

            Map<String, EventPayload> eventMap = new HashMap<>();
            EventPayload sampleEventPayload = Mockito.mock(EventPayload.class);
            eventMap.put("sampleEvent", sampleEventPayload);

            SecurityEventTokenPayload properPayload = SecurityEventTokenPayload.builder()
                    .iss("https://issuer.example.com")
                    .jti("unique-token-id-12345")
                    .iat(System.currentTimeMillis() / 1000L)
                    .aud("https://audience.example.com")
                    .txn("transaction-id-12345")
                    .rci("request-correlation-id-12345")
                    .events(eventMap)
                    .build();

            String tenantDomain = "sampleTenant";
            String eventUri = "https://event.example.com";

            EventHookHandlerUtils.publishEventPayload(properPayload, tenantDomain, eventUri);

            ArgumentCaptor<SecurityEventTokenPayload> payloadCaptor =
                    ArgumentCaptor.forClass(SecurityEventTokenPayload.class);
            ArgumentCaptor<EventContext> contextCaptor = ArgumentCaptor.forClass(EventContext.class);

            verify(mockedEventPublisherService, times(1)).
                    publish(payloadCaptor.capture(), contextCaptor.capture());

            SecurityEventTokenPayload capturedPayload = payloadCaptor.getValue();
            EventContext capturedContext = contextCaptor.getValue();

            assertEquals(capturedPayload.getIss(), "https://issuer.example.com");
            assertEquals(capturedPayload.getAud(), "https://audience.example.com");
            assertEquals(capturedPayload.getTxn(), "transaction-id-12345");

            assertEquals(capturedContext.getTenantDomain(), tenantDomain);
            assertEquals(capturedContext.getEventUri(), eventUri);

            assertEquals(capturedPayload.getEvents(), eventMap);
        }
    }

    @Test
    public void testConstructBaseURLSuccess() {

        TestUtils.mockServiceURLBuilder();
        String baseURL = EventHookHandlerUtils.constructBaseURL();
        assertNotNull(baseURL, "Base URL should not be null");
        closeMockedServiceURLBuilder();
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

    @Test
    public void testGetCorrelationIDWithoutExistingCorrelationID() {

        MDC.clear();
        String correlationID = EventHookHandlerUtils.getCorrelationID();
        assertNotNull(correlationID, "A new correlation ID should be generated");
    }

    @Test
    public void testGetCorrelationIDWhenMDCNotSet() {

        MDC.clear();
        String correlationID = EventHookHandlerUtils.getCorrelationID();
        assertNotNull(correlationID);
        assertTrue(correlationID.matches(
                "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"));
    }

    @Test
    public void testExtractSubjectFromEventData() throws IdentityEventException, UserIdNotFoundException {

        EventData eventData = Mockito.mock(EventData.class);

        when(eventData.getAuthenticatedUser()).thenReturn(mockedAuthenticatedUser);
        when(mockedAuthenticatedUser.getUserId()).thenReturn("user-id-123");
        when(mockedAuthenticatedUser.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);

        when(eventData.getAuthenticationContext()).thenReturn(mockedAuthenticationContext);
        when(mockedAuthenticationContext.getSessionIdentifier()).thenReturn("session-id-123");
        mockIdentityTenantUtil();

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

        EventData eventData = Mockito.mock(EventData.class);
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("streamId", "stream-id-123");
        when(eventData.getEventParams()).thenReturn(Collections.unmodifiableMap(dataMap));

        Subject subject = EventHookHandlerUtils.buildVerificationSubject(eventData);

        assertNotNull(subject, "Subject should not be null");
        assertTrue(subject instanceof SimpleSubject, "Subject should be of type SimpleSubject");
        assertEquals(subject.getProperty("id"), "stream-id-123", "Stream ID should match");
    }
}
