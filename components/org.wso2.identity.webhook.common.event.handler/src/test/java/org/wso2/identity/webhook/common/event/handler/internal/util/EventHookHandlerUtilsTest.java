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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Test class for EventHookHandlerUtils.
 */
public class EventHookHandlerUtilsTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_TENANT_ID = "100";
    private static final Log log = LogFactory.getLog(EventHookHandlerUtilsTest.class);

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

            EventHookHandlerDataHolder mockDataHolderInstance = mock(EventHookHandlerDataHolder.class);
            when(EventHookHandlerDataHolder.getInstance()).thenReturn(mockDataHolderInstance);

            when(mockDataHolderInstance.getEventPublisherService()).thenReturn(mockedEventPublisherService);

            Map<String, EventPayload> eventMap = new HashMap<>();
            EventPayload sampleEventPayload = mock(EventPayload.class);
            eventMap.put("sampleEvent", sampleEventPayload);

            SecurityEventTokenPayload properPayload = new SecurityEventTokenPayload.WSO2Builder()
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

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildEventDataProviderWithNullProperties() throws IdentityEventException {

        Event event = new Event(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name(), null);

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);
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
}
