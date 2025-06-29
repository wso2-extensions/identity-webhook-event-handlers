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
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.topic.management.api.service.TopicManagementService;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.carbon.identity.webhook.metadata.api.service.WebhookMetadataService;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
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
 * Unit test class for {@link VerificationEventHookHandler}.
 */
public class VerificationEventHookHandlerTest {

    private static final String SAMPLE_EVENT_KEY_VERIFICATION =
            "https://schemas.openid.net/secevent/ssf/event-type/verification";
    private static final String SAMPLE_TENANT_DOMAIN = "sample-domain";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @Mock
    private VerificationEventPayloadBuilder mockedVerificationEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private WebhookMetadataService mockedWebhookMetadataService;
    @Mock
    private TopicManagementService mockedTopicManagementService;

    private VerificationEventHookHandler verificationEventHookHandler;

    @BeforeClass
    public void setupClass() {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
    }

    @AfterMethod
    public void tearDown() {

        Mockito.reset(mockedEventHookHandlerUtils);
        Mockito.reset(mockedEventPublisherService);
    }

    @AfterClass
    public void tearDownClass() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @Test
    public void testCanHandle() {

        Event event = createEventWithProperties(IdentityEventConstants.EventName.VERIFICATION.name());
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertTrue(verificationEventHookHandler.canHandle(messageContext));

        event = new Event(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name());
        messageContext = new IdentityEventMessageContext(event);
        assertFalse(verificationEventHookHandler.canHandle(messageContext));
    }

    @Test
    public void testGetName() {

        String expectedName = Constants.VERIFICATION_EVENT_HOOK_NAME;
        String actualName = verificationEventHookHandler.getName();
        assertEquals(actualName, expectedName);
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.EventName.VERIFICATION.name(), SAMPLE_EVENT_KEY_VERIFICATION}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        // Mock event profile and channel
        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event(eventName, "description",
                        expectedEventKey);
        String channelUri = "verification/channel/uri";
        Channel channel = new Channel("Verification Channel", "Verification Channel", channelUri,
                Collections.singletonList(channelEvent));
        EventProfile eventProfile = new EventProfile("CAEP", "uri", Collections.singletonList(channel));
        List<EventProfile> profiles = Collections.singletonList(eventProfile);

        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(profiles);
        when(mockedTopicManagementService.isTopicExists(anyString(), anyString(), anyString())).thenReturn(true);

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getVerificationEventPayloadBuilder(
                            org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.CAEP))
                    .thenReturn(mockedVerificationEventPayloadBuilder);

            when(mockedVerificationEventPayloadBuilder.buildVerificationEventPayload(any(EventData.class)))
                    .thenReturn(mockedEventPayload);

            try (MockedStatic<EventHookHandlerUtils> utilsMocked = mockStatic(EventHookHandlerUtils.class)) {
                // Mock EventMetadata to match the channel and event name
                org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata eventMetadata =
                        mock(org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata.class);
                when(eventMetadata.getChannel()).thenReturn("Verification Channel");
                when(eventMetadata.getEvent()).thenReturn(eventName);

                utilsMocked.when(() -> EventHookHandlerUtils.getEventProfileManagerByProfile(anyString(), anyString()))
                        .thenReturn(eventMetadata);

                // Mock EventData to return correct AuthenticationContext with tenant domain
                EventData eventData = mock(EventData.class);
                AuthenticationContext authContext = mock(AuthenticationContext.class);
                when(authContext.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
                when(eventData.getAuthenticationContext()).thenReturn(authContext);

                utilsMocked.when(() -> EventHookHandlerUtils.buildEventDataProvider(any(Event.class)))
                        .thenReturn(eventData);

                SecurityEventTokenPayload tokenPayload = mock(SecurityEventTokenPayload.class);
                utilsMocked.when(() -> EventHookHandlerUtils.buildSecurityEventToken(any(), anyString(), any()))
                        .thenReturn(tokenPayload);

                verificationEventHookHandler.handleEvent(event);

                utilsMocked.verify(() -> EventHookHandlerUtils.publishEventPayload(eq(tokenPayload),
                        eq(SAMPLE_TENANT_DOMAIN), eq(channelUri)), times(1));
            }
        }
    }

    @Test
    public void testHandleEventWithNoProfiles() throws Exception {

        Event event = createEventWithProperties(IdentityEventConstants.EventName.VERIFICATION.name());
        when(mockedWebhookMetadataService.getSupportedEventProfiles()).thenReturn(Collections.emptyList());
        verificationEventHookHandler.handleEvent(event);
        verify(mockedEventPublisherService, times(0)).publish(any(), any());
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        HashMap<String, Object> params = new HashMap<>();
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        AuthenticationContext authenticationContext = mock(AuthenticationContext.class);
        when(authenticationContext.getTenantDomain()).thenReturn(SAMPLE_TENANT_DOMAIN);
        params.put("user", authenticatedUser);
        properties.put("context", authenticationContext);
        properties.put("authenticationStatus", AuthenticatorStatus.PASS);
        properties.put("params", params);
        properties.put("sessionContext", mock(SessionContext.class));
        return new Event(eventName, properties);
    }

    private void setupUtilities() {

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(Mockito.CALLS_REAL_METHODS));
        verificationEventHookHandler = new VerificationEventHookHandler();
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
        EventHookHandlerDataHolder.getInstance().setWebhookMetadataService(mockedWebhookMetadataService);
        EventHookHandlerDataHolder.getInstance().setTopicManagementService(mockedTopicManagementService);
    }

    private void setupPayloadBuilderMocks() {

        when(mockedVerificationEventPayloadBuilder.getEventSchemaType()).thenReturn(
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.CAEP);
        when(mockedVerificationEventPayloadBuilder.buildVerificationEventPayload(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }
}
