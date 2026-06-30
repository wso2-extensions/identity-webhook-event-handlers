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
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentPurposeEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.Collections;
import java.util.HashMap;

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
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.CONSENT_PURPOSE_EVENT_HOOK_NAME;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.InterceptorConstants.POST_ADD_PURPOSE_VERSION;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link ConsentPurposeEventHookHandler}.
 */
public class ConsentPurposeEventHookHandlerTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String CONSENT_PURPOSE_CHANNEL_URI =
            "https://schemas.identity.wso2.org/events/consent-purpose";
    private static final String PURPOSE_VERSION_ADDED_EVENT_URI =
            "https://schemas.identity.wso2.org/events/consent-purpose/event-type/purposeVersionAdded";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private ConsentPurposeEventPayloadBuilder mockedConsentPurposeEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private ConsentPurposeEventHookHandler consentPurposeEventHookHandler;

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

        assertEquals(consentPurposeEventHookHandler.getName(), CONSENT_PURPOSE_EVENT_HOOK_NAME);
    }

    @Test
    public void testCanHandle_postAddPurposeVersion() {

        Event event = new Event(POST_ADD_PURPOSE_VERSION);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertTrue(consentPurposeEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testCannotHandle_unrelatedEvent() {

        Event event = new Event("POST_ADD_RECEIPT");
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertFalse(consentPurposeEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testCannotHandle_nullEvent() {

        assertFalse(consentPurposeEventHookHandler.canHandle(new IdentityEventMessageContext(new Event(null))));
    }

    @Test
    public void testHandleEvent_publishesPurposeVersionAdded() throws Exception {

        Event event = createEventWithProperties(POST_ADD_PURPOSE_VERSION);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_PURPOSE_VERSION, "description", PURPOSE_VERSION_ADDED_EVENT_URI);
        Channel channel = new Channel("Consent purpose", "Consent purpose channel", CONSENT_PURPOSE_CHANNEL_URI,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));

        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentPurposeEventPayloadBuilder(
                            Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentPurposeEventPayloadBuilder);
            when(mockedConsentPurposeEventPayloadBuilder.buildPurposeVersionAddedEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventData eventData = mock(EventData.class);
                when(eventData.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);

                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(CONSENT_PURPOSE_CHANNEL_URI);
                when(eventMetadata.getEvent()).thenReturn(PURPOSE_VERSION_ADDED_EVENT_URI);

                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                consentPurposeEventHookHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(1))
                        .publish(eq(tokenPayload), argThat(ctx ->
                                SAMPLE_TENANT_DOMAIN.equals(ctx.getTenantDomain()) &&
                                        CONSENT_PURPOSE_CHANNEL_URI.equals(ctx.getEventUri()) &&
                                        "WSO2".equals(ctx.getEventProfileName()) &&
                                        "v1".equals(ctx.getEventProfileVersion())
                        ));
            }
        }
    }

    @Test
    public void testHandleEvent_noProfiles() throws Exception {

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        consentPurposeEventHookHandler.handleEvent(new Event(POST_ADD_PURPOSE_VERSION));
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    @Test
    public void testHandleEvent_noPayloadBuilder() throws Exception {

        Event event = createEventWithProperties(POST_ADD_PURPOSE_VERSION);
        Channel channel = new Channel("Consent purpose", "Consent purpose channel", CONSENT_PURPOSE_CHANNEL_URI,
                Collections.singletonList(new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_PURPOSE_VERSION, "desc", PURPOSE_VERSION_ADDED_EVENT_URI)));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentPurposeEventPayloadBuilder(any()))
                    .thenReturn(null);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(mock(EventData.class));

                consentPurposeEventHookHandler.handleEvent(event);
                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEvent_noEventMetadata() throws Exception {

        Event event = createEventWithProperties(POST_ADD_PURPOSE_VERSION);
        Channel channel = new Channel("Consent purpose", "Consent purpose channel", CONSENT_PURPOSE_CHANNEL_URI,
                Collections.singletonList(new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_PURPOSE_VERSION, "desc", PURPOSE_VERSION_ADDED_EVENT_URI)));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentPurposeEventPayloadBuilder(
                            Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentPurposeEventPayloadBuilder);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(mock(EventData.class));
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(null);

                consentPurposeEventHookHandler.handleEvent(event);
                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    @Test
    public void testHandleEvent_channelNotFound() throws Exception {

        Event event = createEventWithProperties(POST_ADD_PURPOSE_VERSION);
        Channel channel = new Channel("Consent purpose", "Consent purpose channel", "https://other.channel/uri",
                Collections.singletonList(new org.wso2.carbon.identity.webhook.metadata.api.model.Event(
                        POST_ADD_PURPOSE_VERSION, "desc", PURPOSE_VERSION_ADDED_EVENT_URI)));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        when(mockedWebhookMetadataService.getSupportedEventProfiles())
                .thenReturn(Collections.singletonList(eventProfile));

        try (MockedStatic<PayloadBuilderFactory> factoryMocked = mockStatic(PayloadBuilderFactory.class)) {
            factoryMocked.when(() -> PayloadBuilderFactory.getConsentPurposeEventPayloadBuilder(
                            Constants.EventSchema.WSO2))
                    .thenReturn(mockedConsentPurposeEventPayloadBuilder);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventMetadata eventMetadata = mock(EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(CONSENT_PURPOSE_CHANNEL_URI);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(mock(EventData.class));
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);

                consentPurposeEventHookHandler.handleEvent(event);
                verify(mockedEventPublisherService, times(0)).publish(any(), any());
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

        when(mockedConsentPurposeEventPayloadBuilder.getEventSchemaType()).thenReturn(Constants.EventSchema.WSO2);
        when(mockedConsentPurposeEventPayloadBuilder.buildPurposeVersionAddedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        consentPurposeEventHookHandler = new ConsentPurposeEventHookHandler();
    }
}
