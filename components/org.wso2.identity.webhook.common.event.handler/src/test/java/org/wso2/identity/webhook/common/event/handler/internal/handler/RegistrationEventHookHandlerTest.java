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
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
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
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

public class RegistrationEventHookHandlerTest {

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private RegistrationEventPayloadBuilder mockedRegistrationEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private RegistrationEventHookHandler registrationEventHookHandler;

    private static final String SAMPLE_EVENT_KEY =
            "https://schemas.identity.wso2.org/events/registration/event-type/registrationSuccess";
    private static final String REGISTRATION_FAILURE_EVENT_KEY =
            "https://schemas.identity.wso2.org/events/registration/event-type/registrationFailure";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";
    private static final String ADMIN = "ADMIN";

    @BeforeClass
    public void setupClass() throws Exception {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.USER_REGISTRATION)
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

        Mockito.reset(mockedEventHookHandlerUtils);
        Mockito.reset(mockedEventPublisherService);
    }

    @Test
    public void testGetName() {

        String name = registrationEventHookHandler.getName();
        assertEquals(name, Constants.REGISTRATION_EVENT_HOOK_NAME);
    }

    @Test
    public void testCanHandle() {

        Event event = new Event(IdentityEventConstants.Event.POST_ADD_USER);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = registrationEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle, "The event handler should be able to handle the event POST_ADD_USER.");
    }

    @Test
    public void testCanNotHandle() {

        Event event = new Event(IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = registrationEventHookHandler.canHandle(messageContext);
        assertFalse(canHandle, "The event handler should not be able to handle the event POST_UNLOCK_ACCOUNT.");
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.Event.POST_ADD_USER, SAMPLE_EVENT_KEY},
                {IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM, SAMPLE_EVENT_KEY}};
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event("Registration success", "description",
                        expectedEventKey);
        String channelUri = "registration/channel/uri";
        Channel channel = new Channel("Registrations", "Registration Channel", channelUri,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString(), anyString())).thenReturn(
                true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getRegistrationEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedRegistrationEventPayloadBuilder);

            when(mockedRegistrationEventPayloadBuilder.buildRegistrationSuccessEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                EventMetadata eventMetadata = mock(EventMetadata.class);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                when(eventMetadata.getChannel()).thenReturn("Registrations");
                when(eventMetadata.getEvent()).thenReturn("Registration success");
                when(eventMetadata.getEventProfile()).thenReturn("WSO2");

                // Mock getEventMetadata to return our eventMetadata
                RegistrationEventHookHandler spyHandler = Mockito.spy(registrationEventHookHandler);

                EventData eventData = mock(EventData.class);
                HashMap<String, Object> params = new HashMap<>();
                params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
                when(eventData.getEventParams()).thenReturn(params);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                spyHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(1))
                        .publish(eq(tokenPayload), argThat(ctx ->
                                ctx.getTenantDomain().equals(CARBON_SUPER) &&
                                        ctx.getEventUri().equals(channelUri) &&
                                        ctx.getEventProfileName().equals("WSO2") &&
                                        ctx.getEventProfileVersion().equals("v1")
                        ));
            }
        }
    }

    @Test
    public void testHandleEventWithNoProfiles() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_ADD_USER);
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        registrationEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        String[] addedUsers = new String[] {DOMAIN_QUALIFIED_ADDED_USER_NAME};
        properties.put(IdentityEventConstants.EventProperty.NEW_USERS, addedUsers);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
        return new Event(eventName, properties);
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedRegistrationEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedRegistrationEventPayloadBuilder.buildRegistrationSuccessEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedRegistrationEventPayloadBuilder.buildRegistrationFailureEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() throws Exception {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS));
        CommonTestUtils.initPrivilegedCarbonContext();
        registrationEventHookHandler = new RegistrationEventHookHandler();
    }
}
