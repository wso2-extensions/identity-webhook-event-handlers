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
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.*;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

public class TokenEventHookHandlerTest {

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private TokenEventHookHandler tokenEventHookHandler;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private TokenEventPayloadBuilder mockedTokenEventPayloadBuilder;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private static final String SAMPLE_EVENT_KEY =
            "schemas.identity.wso2.org/events/token/event-type/accessTokenRevoked";
    private static final String SAMPLE_ATTRIBUTE_JSON = "{\"sendCredentials\":false,\"publishEnabled\":true}";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";

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
    public void testTestGetName() {

        String name = tokenEventHookHandler.getName();
        assertEquals(name, Constants.TOKEN_EVENT_HOOK_NAME);
    }

    @Test
    public void testCanHandle() {

        Event event = new Event(IdentityEventConstants.Event.TOKEN_ISSUED);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = tokenEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle, "The event handler should be able to handle the event " + IdentityEventConstants.Event.TOKEN_ISSUED);
    }

    @Test
    public void testCanNotHandle() {

        Event event = new Event(IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = tokenEventHookHandler.canHandle(messageContext);
        assertFalse(canHandle, "The event handler should not be able to handle the event POST_UNLOCK_ACCOUNT.");
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.Event.TOKEN_ISSUED, SAMPLE_EVENT_KEY}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        // Mock event profile and channel
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        Channel channel = new Channel("Token Channel", "Token Channel", "token/channel/uri",
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("WSO2", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString(), anyString())).thenReturn(
                true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getTokenEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2))
                    .thenReturn(mockedTokenEventPayloadBuilder);

            when(mockedTokenEventPayloadBuilder.buildAccessTokenRevokeEvent(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                // Mock all static methods used in the handler
                EventData eventDataProvider = mock(EventData.class);
                EventMetadata eventMetadata = mock(EventMetadata.class);
                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);

                // Set up eventDataProvider to return the correct tenant domain
                when(eventDataProvider.getProperties()).thenReturn(
                        new HashMap<String, Object>() {{
                            put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
                        }}
                                                                   );
                // Set up eventMetadata to match the channel and event name
                when(eventMetadata.getChannel()).thenReturn("Token Channel");
                when(eventMetadata.getEvent()).thenReturn(eventName);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventDataProvider);
                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString()))
                        .thenReturn(tokenPayload);

                tokenEventHookHandler.handleEvent(event);

                verify(mockedEventPublisherService, times(0)).publish(any(), any());
            }
        }
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();

        String[] addedUsers = new String[]{DOMAIN_QUALIFIED_ADDED_USER_NAME};
        properties.put(IdentityEventConstants.EventProperty.NEW_USERS, addedUsers);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, CARBON_SUPER);
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

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);

        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedTokenEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2);
        when(mockedTokenEventPayloadBuilder.buildAccessTokenRevokeEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        tokenEventHookHandler = new TokenEventHookHandler();
    }

}