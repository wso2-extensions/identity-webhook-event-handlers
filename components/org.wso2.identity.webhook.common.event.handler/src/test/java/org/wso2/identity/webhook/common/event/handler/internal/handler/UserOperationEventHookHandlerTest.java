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

import org.json.simple.JSONObject;
import org.mockito.ArgumentCaptor;
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
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.config.ResourceConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.ArrayList;
import java.util.HashMap;

import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.reset;
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
    private static final String SAMPLE_ATTRIBUTE_JSON = "{\"sendCredentials\":false,\"publishEnabled\":true}";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";
    private static final String ADMIN = "ADMIN";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @InjectMocks
    private UserOperationEventHookHandler userOperationEventHookHandler;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private UserOperationEventPayloadBuilder mockedUserOperationEventPayloadBuilder;
    @Mock
    private EventConfigManager mockedEventConfigManager;

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

        return new Object[][]{
                {IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE,
                        Constants.EventHandlerKey.WSO2.POST_UPDATE_USER_LIST_OF_ROLE_EVENT, SAMPLE_EVENT_KEY}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String eventHandlerKey, String expectedEventKey)
            throws ConfigurationManagementException, IdentityEventException {

        Event event = createEventWithProperties(eventName);
        Resources resources = createResourcesWithAttributes(eventHandlerKey);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig(true,
                new ResourceConfig(new JSONObject()));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getUserOperationEventPayloadBuilder(anyString()))
                    .thenReturn(mockedUserOperationEventPayloadBuilder);
            when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);
            when(mockedEventConfigManager.getEventUri(anyString())).thenReturn(expectedEventKey);
            when(mockedEventConfigManager.getEventPublisherConfigForTenant(anyString(), anyString())).thenReturn(
                    eventPublisherConfig);
            when(mockedEventConfigManager.extractEventPublisherConfig(any(Resources.class), anyString()))
                    .thenReturn(eventPublisherConfig);

            userOperationEventHookHandler.handleEvent(event);

            verifyEventPublishedWithExpectedKey(expectedEventKey);
        }
    }

    @Test
    public void testHandleEventWithPublishingDisabled() throws
            ConfigurationManagementException, IdentityEventException {

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE);
        Resources resources =
                createResourcesWithAttributes(Constants.EventHandlerKey.WSO2.POST_UPDATE_USER_LIST_OF_ROLE_EVENT);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig(false,
                new ResourceConfig(new JSONObject()));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getUserOperationEventPayloadBuilder(anyString()))
                    .thenReturn(mockedUserOperationEventPayloadBuilder);
            reset(mockedConfigurationManager);
            when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);
            when(mockedEventConfigManager.getEventPublisherConfigForTenant(anyString(), anyString())).thenReturn(
                    eventPublisherConfig);
            when(mockedEventConfigManager.extractEventPublisherConfig(any(Resources.class), anyString()))
                    .thenReturn(eventPublisherConfig);

            userOperationEventHookHandler.handleEvent(event);

            verify(mockedEventPublisherService, times(0)).publish(any(), any());
        }
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testHandleEventThrowsExceptionAtNoProperties() throws IdentityEventException, ConfigurationManagementException {

        Event event = new Event(IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE, null);
        Resources resources =
                createResourcesWithAttributes(Constants.EventHandlerKey.WSO2.POST_UPDATE_USER_LIST_OF_ROLE_EVENT);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig(false,
                new ResourceConfig(new JSONObject()));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getUserOperationEventPayloadBuilder(anyString()))
                    .thenReturn(mockedUserOperationEventPayloadBuilder);
            reset(mockedConfigurationManager);
            when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);
            when(mockedEventConfigManager.getEventPublisherConfigForTenant(anyString(), anyString())).thenReturn(
                    eventPublisherConfig);
            when(mockedEventConfigManager.extractEventPublisherConfig(any(Resources.class), anyString()))
                    .thenReturn(eventPublisherConfig);

            userOperationEventHookHandler.handleEvent(event);
        }
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testExceptionOnNullTenant() throws IdentityEventException {
        EventConfigManager eventConfigManager =  EventConfigManager.getInstance();
        eventConfigManager.getEventPublisherConfigForTenant(null, IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE);
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedUserOperationEventPayloadBuilder.getEventSchemaType()).thenReturn("WSO2");
        when(mockedUserOperationEventPayloadBuilder.buildUserGroupUpdateEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        userOperationEventHookHandler = new UserOperationEventHookHandler(mockedEventConfigManager);
    }

    private Event createEvent(String eventName) {

        return new Event(eventName);
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();

        String[] addedUsers = new String[]{DOMAIN_QUALIFIED_ADDED_USER_NAME};
        properties.put(IdentityEventConstants.EventProperty.NEW_USERS, addedUsers);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
        properties.put(IdentityEventConstants.EventProperty.INITIATOR_TYPE, ADMIN);

        return new Event(eventName, properties);
    }

    private Resources createResourcesWithAttributes(String eventHandlerKey) {

        Resources resources = new Resources();
        Resource resource = new Resource();
        ArrayList<Attribute> attributeList = new ArrayList<>();
        Attribute attribute = new Attribute(eventHandlerKey, SAMPLE_ATTRIBUTE_JSON);
        attributeList.add(attribute);
        resource.setAttributes(attributeList);
        resource.setHasAttribute(true);
        ArrayList<Resource> resourceList = new ArrayList<>();
        resourceList.add(resource);
        resources.setResources(resourceList);
        return resources;
    }

    private void verifyEventPublishedWithExpectedKey(String expectedEventKey) {

        ArgumentCaptor<SecurityEventTokenPayload> argumentCaptor = ArgumentCaptor
                .forClass(SecurityEventTokenPayload.class);
        verify(mockedEventPublisherService, times(1)).publish(argumentCaptor.capture(),
                any(EventContext.class));

        SecurityEventTokenPayload capturedEventPayload = argumentCaptor.getValue();
        assertEquals(capturedEventPayload.getEvents().keySet().iterator().next(), expectedEventKey);
    }

    @Test
    public void testGetName() {

        String name = userOperationEventHookHandler.getName();
        assertEquals(name, Constants.USER_OPERATION_EVENT_HOOK_NAME);
    }
}
