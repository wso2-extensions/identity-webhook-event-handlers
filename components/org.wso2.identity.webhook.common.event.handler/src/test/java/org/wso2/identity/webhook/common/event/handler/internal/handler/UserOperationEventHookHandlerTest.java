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
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
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
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
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

/**
 * Unit tests for the UserOperationEventHookHandler class and related classes.
 */
public class UserOperationEventHookHandlerTest {

    private static final String SAMPLE_EVENT_KEY =
            "schemas.identity.wso2.org/events/user-operations/event-type/updateUserGroup";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private UserOperationEventPayloadBuilder mockedUserOperationEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private UserOperationEventHookHandler userOperationEventHookHandler;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventHookHandlerUtils);
        Mockito.reset(mockedEventPublisherService);
    }

    @Test
    public void testCanHandle() {

        Event event = createEvent(IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = userOperationEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle, "The event handler should be able to handle the event POST_UPDATE_USER_LIST_OF_ROLE.");
    }

    @Test
    public void testCannotHandle() {

        Event event = createEvent(IdentityEventConstants.EventName.SESSION_TERMINATE.name());
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = userOperationEventHookHandler.canHandle(messageContext);
        assertFalse(canHandle, "The event handler should not be able to handle the SESSION_TERMINATE event.");
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE, SAMPLE_EVENT_KEY}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        // Mock event profile and channel
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        String channelUri = "user/operation/channel/uri";
        Channel channel = new Channel("User Operation Channel", "User Operation Channel", channelUri,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString(), anyString())).thenReturn(
                true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getUserOperationEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedUserOperationEventPayloadBuilder);

            when(mockedUserOperationEventPayloadBuilder.buildUserGroupUpdateEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                // Mock EventMetadata to match the channel and event name
                org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata eventMetadata =
                        mock(org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn(channelUri);
                when(eventMetadata.getEvent()).thenReturn(expectedEventKey);

                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);

                // Mock EventData to return correct tenant domain
                EventData eventData = mock(EventData.class);
                when(eventData.getTenantDomain()).thenReturn(CARBON_SUPER);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);

                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                // Mock canHandleEvent to return true
                when(mockedEventPublisherService.canHandleEvent(any(EventContext.class))).thenReturn(true);

                userOperationEventHookHandler.handleEvent(event);

                // Verify publish is called with correct arguments
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

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE);
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        userOperationEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedUserOperationEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedUserOperationEventPayloadBuilder.buildUserGroupUpdateEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS));
        userOperationEventHookHandler = new UserOperationEventHookHandler();
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

    @Test
    public void testGetName() {

        String name = userOperationEventHookHandler.getName();
        assertEquals(name, Constants.USER_OPERATION_EVENT_HOOK_NAME);
    }
}
