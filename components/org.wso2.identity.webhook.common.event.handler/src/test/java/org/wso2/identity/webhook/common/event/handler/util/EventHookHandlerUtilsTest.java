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
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;

/**
 * Test class for EventHookHandlerUtils.
 */
public class EventHookHandlerUtilsTest {

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
            EventPayload sampleEventPayload = Mockito.mock(EventPayload.class);  // Mock EventPayload
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

            verify(mockedEventPublisherService, times(1))
                    .publish(payloadCaptor.capture(), contextCaptor.capture());

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
            // Simulate setting the correlation ID in the MDC with the correct key
            mockedMDC.when(() -> MDC.get("Correlation-ID")).thenReturn(expectedCorrelationID);

            String correlationID = EventHookHandlerUtils.getCorrelationID();

            assertNotNull(correlationID, "Correlation ID should not be null");
            assertEquals(correlationID, expectedCorrelationID, "Correlation ID should match the expected value");

            // Verify that the put method was not called since the ID already exists
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

}
