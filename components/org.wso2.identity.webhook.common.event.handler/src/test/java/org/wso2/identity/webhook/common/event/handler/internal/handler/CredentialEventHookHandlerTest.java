/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.CommonTestUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit test class for CredentialEventHookHandler.
 */
public class CredentialEventHookHandlerTest {

    private static final String SAMPLE_EVENT_KEY =
            "https://schemas.identity.wso2.org/events/credential/event-type/credentialUpdated";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private CredentialEventPayloadBuilder mockedCredentialEventPayloadBuilder;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    @InjectMocks
    private CredentialEventHookHandler credentialEventHookHandler;

    @BeforeClass
    public void setupClass() throws Exception {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.PASSWORD_RESET)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventPublisherService, mockedWebhookMetadataService, mockedTopicManagementService);
    }

    @Test
    public void testCanHandle() {

        Event event = createEvent(IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertTrue(credentialEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testCannotHandle() {

        Event event = createEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name());
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertFalse(credentialEventHookHandler.canHandle(messageContext));
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM, SAMPLE_EVENT_KEY}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        String channelUri = "credential/change/channel/uri";
        Channel channel =
                new Channel("Credential Change Channel", "Credential Change Channel", channelUri,
                        Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString())).thenReturn(true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getCredentialEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedCredentialEventPayloadBuilder);

            when(mockedCredentialEventPayloadBuilder.buildCredentialUpdateEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata eventMetadata =
                        mock(org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn("Credential Change Channel");
                when(eventMetadata.getEvent()).thenReturn(eventName);

                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenCallRealMethod();

                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                credentialEventHookHandler.handleEvent(event);

                utilsMocked.verify(() -> EventHookHandlerUtils.publishEventPayload(tokenPayload,
                        CARBON_SUPER, channelUri), times(1));
            }
        }
        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testHandleEventWithNoProfiles() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD);
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        credentialEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    @Test
    public void testHandleEventThrowsExceptionAtNoProperties() throws IdentityEventException {

        Event event = new Event(IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD, null);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getCredentialEventPayloadBuilder(any(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.class)))
                    .thenReturn(mockedCredentialEventPayloadBuilder);

            credentialEventHookHandler.handleEvent(event);

            // Optionally verify that publish is never called
            verify(mockedEventPublisherService, times(0)).publish(any(), any());
        }
    }

    @Test
    public void testGetName() {

        String name = credentialEventHookHandler.getName();
        assertEquals(name, Constants.CREDENTIAL_EVENT_HOOK_NAME);
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedCredentialEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedCredentialEventPayloadBuilder.buildCredentialUpdateEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() throws Exception {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        CommonTestUtils.initPrivilegedCarbonContext();
    }

    private Event createEvent(String eventName) {

        return new Event(eventName);
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        String[] addedUsers = new String[] {DOMAIN_QUALIFIED_ADDED_USER_NAME};
        properties.put(IdentityEventConstants.EventProperty.NEW_USERS, addedUsers);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
        return new Event(eventName, properties);
    }
}
