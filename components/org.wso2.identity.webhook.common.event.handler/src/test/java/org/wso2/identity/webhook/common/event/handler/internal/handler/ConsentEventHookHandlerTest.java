/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EventDataProperties;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.CONSENT_EVENT_HOOK_NAME;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_ADD_RECEIPT;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_AUTHORIZE_CONSENT;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link ConsentEventHookHandler}.
 */
public class ConsentEventHookHandlerTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String CONSENT_CHANNEL_URI = "https://schemas.identity.wso2.org/events/consent";
    private static final String CONSENT_ADDED_EVENT_URI =
            "https://schemas.identity.wso2.org/events/consent/event-type/consentAdded";
    private static final String CONSENT_REVOKED_EVENT_URI =
            "https://schemas.identity.wso2.org/events/consent/event-type/consentRevoked";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private ConsentEventPayloadBuilder mockedConsentEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private ConsentEventHookHandler consentEventHookHandler;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventPublisherService);
        Mockito.reset(mockedWebhookMetadataService);
    }

    @AfterClass
    public void tearDownClass() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @Test
    public void testGetName() {

        assertEquals(consentEventHookHandler.getName(), CONSENT_EVENT_HOOK_NAME);
    }

    @Test
    public void testCanHandle_postAddReceipt() {

        Event event = new Event(POST_ADD_RECEIPT);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertTrue(consentEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testCanHandle_postAuthorizeConsent() {

        Event event = new Event(POST_AUTHORIZE_CONSENT);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertTrue(consentEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testCannotHandle_unrelatedEvent() {

        Event event = new Event("POST_ADD_PURPOSE_VERSION");
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertFalse(consentEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testCannotHandle_nullEvent() {

        assertFalse(consentEventHookHandler.canHandle(new IdentityEventMessageContext(new Event(null))));
    }

    @Test
    public void testCannotHandle_postRevokeReceipt() {

        // revokeReceipt is deprecated (superseded by authorizeConsent with REVOKED) and is intentionally not webhooked.
        Event event = new Event("POST_REVOKE_RECEIPT");
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertFalse(consentEventHookHandler.canHandle(messageContext));
    }

    @DataProvider(name = "consentEventProvider")
    public Object[][] consentEventProvider() {

        return new Object[][] {
                {POST_ADD_RECEIPT, CONSENT_ADDED_EVENT_URI},
                {POST_AUTHORIZE_CONSENT, CONSENT_ADDED_EVENT_URI}
        };
    }

    @Test(dataProvider = "consentEventProvider")
    public void testHandleEvent_publishesForEachPayload(String eventName, String expectedEventUri) throws Exception {

        Event event = createEventWithProperties(eventName);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        eventName, "description", expectedEventUri);
        Channel channel = new Channel("Consents", "Consent channel", CONSENT_CHANNEL_URI,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));

        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentEventPayloadBuilder(Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentEventPayloadBuilder);

            when(mockedConsentEventPayloadBuilder.buildConsentAddedEvent(any(EventData.class)))
                    .thenReturn(Collections.singletonList(mockedEventPayload));

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventData eventData = mock(EventData.class);
                when(eventData.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);

                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(CONSENT_CHANNEL_URI);
                when(eventMetadata.getEvent()).thenReturn(expectedEventUri);

                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                consentEventHookHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(1))
                        .publish(eq(tokenPayload), argThat(ctx ->
                                SAMPLE_TENANT_DOMAIN.equals(ctx.getTenantDomain()) &&
                                        CONSENT_CHANNEL_URI.equals(ctx.getEventUri()) &&
                                        "WSO2".equals(ctx.getEventProfileName()) &&
                                        "v1".equals(ctx.getEventProfileVersion())
                        ));
            }
        }
    }

    @Test
    public void testHandleEvent_noProfiles() throws Exception {

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        consentEventHookHandler.handleEvent(new Event(POST_ADD_RECEIPT));
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    @Test
    public void testHandleEvent_noPayloadBuilder() throws Exception {

        Event event = createEventWithProperties(POST_ADD_RECEIPT);
        Channel channel = new Channel("Consents", "Consent channel", CONSENT_CHANNEL_URI,
                Collections.singletonList(new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_RECEIPT, "desc", CONSENT_ADDED_EVENT_URI)));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentEventPayloadBuilder(any()))
                    .thenReturn(null);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(mock(EventData.class));

                consentEventHookHandler.handleEvent(event);
                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEvent_noEventMetadata() throws Exception {

        Event event = createEventWithProperties(POST_ADD_RECEIPT);
        Channel channel = new Channel("Consents", "Consent channel", CONSENT_CHANNEL_URI,
                Collections.singletonList(new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_RECEIPT, "desc", CONSENT_ADDED_EVENT_URI)));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentEventPayloadBuilder(Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentEventPayloadBuilder);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(mock(EventData.class));
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(null);

                consentEventHookHandler.handleEvent(event);
                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEvent_channelNotFound() throws Exception {

        Event event = createEventWithProperties(POST_ADD_RECEIPT);
        Channel channel = new Channel("Consents", "Consent channel", "https://other.channel/uri",
                Collections.singletonList(new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_RECEIPT, "desc", CONSENT_ADDED_EVENT_URI)));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentEventPayloadBuilder(Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentEventPayloadBuilder);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(CONSENT_CHANNEL_URI);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(mock(EventData.class));
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);

                consentEventHookHandler.handleEvent(event);
                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEvent_multiplePayloadsPerPurpose() throws Exception {

        Event event = createEventWithProperties(POST_ADD_RECEIPT);
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_RECEIPT, "description", CONSENT_ADDED_EVENT_URI);
        Channel channel = new Channel("Consents", "Consent channel", CONSENT_CHANNEL_URI,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        EventPayload secondPayload = mock(EventPayload.class);

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentEventPayloadBuilder(Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentEventPayloadBuilder);
            when(mockedConsentEventPayloadBuilder.buildConsentAddedEvent(any(EventData.class)))
                    .thenReturn(List.of(mockedEventPayload, secondPayload));

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventData eventData = mock(EventData.class);
                when(eventData.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(CONSENT_CHANNEL_URI);
                when(eventMetadata.getEvent()).thenReturn(CONSENT_ADDED_EVENT_URI);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);
                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                consentEventHookHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(2)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEvent_revokeRoutesToRevokedBuilder() throws Exception {

        // A revoke surfaces as a POST_AUTHORIZE_CONSENT event whose resolved type is consentRevoked; the handler
        // must invoke buildConsentRevokedEvent rather than buildConsentAddedEvent.
        Event event = createEventWithProperties(POST_AUTHORIZE_CONSENT);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_AUTHORIZE_CONSENT, "description", CONSENT_REVOKED_EVENT_URI);
        Channel channel = new Channel("Consents", "Consent channel", CONSENT_CHANNEL_URI,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        // Use a fresh builder mock so the times(0) assertion is not affected by invocations from other tests.
        ConsentEventPayloadBuilder revokeBuilder = mock(ConsentEventPayloadBuilder.class);
        when(revokeBuilder.getEventSchemaType()).thenReturn(Constants.EventSchema.WSO2);
        when(revokeBuilder.buildConsentRevokedEvent(any(EventData.class)))
                .thenReturn(Collections.singletonList(mockedEventPayload));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentEventPayloadBuilder(Constants.EventSchema.WSO2))
                    .thenReturn(revokeBuilder);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventData eventData = mock(EventData.class);
                when(eventData.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(CONSENT_CHANNEL_URI);
                when(eventMetadata.getEvent()).thenReturn(CONSENT_REVOKED_EVENT_URI);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);
                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                consentEventHookHandler.handleEvent(event);

                verify(revokeBuilder, times(1)).buildConsentRevokedEvent(any(EventData.class));
                verify(revokeBuilder, times(0)).buildConsentAddedEvent(any(EventData.class));
                verify(mockedEventPublisherService, times(1)).publish(eq(tokenPayload), any());
            }
        }
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.TENANT_DOMAIN,
                SAMPLE_TENANT_DOMAIN);
        return new Event(eventName, properties);
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedConsentEventPayloadBuilder.getEventSchemaType()).thenReturn(Constants.EventSchema.WSO2);
        when(mockedConsentEventPayloadBuilder.buildConsentAddedEvent(any(EventData.class)))
                .thenReturn(Collections.singletonList(mockedEventPayload));
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        consentEventHookHandler = new ConsentEventHookHandler();
    }
}
