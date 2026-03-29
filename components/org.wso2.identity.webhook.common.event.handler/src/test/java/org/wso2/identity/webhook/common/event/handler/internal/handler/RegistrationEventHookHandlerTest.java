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
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySetting;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySettingGroup;
import org.wso2.carbon.identity.compatibility.settings.core.service.CompatibilitySettingsService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.event.publisher.api.service.EventPublisherService;
import org.wso2.carbon.identity.flow.mgt.FlowMgtService;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowCompletionConfig;
import org.wso2.carbon.identity.flow.mgt.Constants.FlowTypes;
import org.wso2.carbon.identity.flow.mgt.model.FlowConfigDTO;
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
    @Mock
    private CompatibilitySettingsService mockedCompatibilitySettingsService;
    @Mock
    private FlowMgtService mockedFlowMgtService;

    private RegistrationEventHookHandler registrationEventHookHandler;

    private static final String SAMPLE_EVENT_KEY =
            "https://schemas.identity.wso2.org/events/registration/event-type/registrationSuccess";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "PRIMARY/john";
    private static final String CARBON_SUPER = "carbon.super";

    @BeforeClass
    public void setupClass() throws Exception {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(new Flow.Builder()
                .name(Flow.Name.REGISTER)
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

        Event event = new Event(IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = registrationEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle, "The event handler should be able to handle the event USER_REGISTRATION_SUCCESS.");
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
                {IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS, SAMPLE_EVENT_KEY},
                {IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM, SAMPLE_EVENT_KEY}};
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String expectedEventKey) throws Exception {

        Event event = createEventWithProperties(eventName);

        org.wso2.carbon.identity.webhook.metadata.api.model.Event channelEvent =
                new org.wso2.carbon.identity.webhook.metadata.api.model.Event("Registration success", "description",
                        expectedEventKey);
        String channelUri = "https://schemas.identity.wso2.org/events/registration";
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

                when(eventMetadata.getChannel()).thenReturn(channelUri);
                when(eventMetadata.getEvent()).thenReturn(expectedEventKey);
                when(eventMetadata.getEventProfile()).thenReturn("WSO2");

                // Mock getEventMetadata to return our eventMetadata
                RegistrationEventHookHandler spyHandler = Mockito.spy(registrationEventHookHandler);

                EventData eventData = mock(EventData.class);
                when(eventData.getTenantDomain()).thenReturn(CARBON_SUPER);

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

        Event event = createEventWithProperties(IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS);
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
        EventHookHandlerDataHolder.getInstance().setCompatibilitySettingsService(mockedCompatibilitySettingsService);
        EventHookHandlerDataHolder.getInstance().setFlowMgtService(mockedFlowMgtService);
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

    /**
     * Drains all flows from the thread-local identity context stack, then enters only the given flow.
     * This is necessary because other test classes may push flows without popping them in @AfterClass,
     * leaving stale entries when tests share the same thread.
     */
    private void switchToFlow(Flow targetFlow) {

        while (IdentityContext.getThreadLocalIdentityContext().getCurrentFlow() != null) {
            IdentityContext.getThreadLocalIdentityContext().exitFlow();
        }
        IdentityContext.getThreadLocalIdentityContext().enterFlow(targetFlow);
    }

    @Test
    public void testCanHandleWithNullEvent() {

        IdentityEventMessageContext messageContext = mock(IdentityEventMessageContext.class);
        when(messageContext.getEvent()).thenReturn(null);
        assertFalse(registrationEventHookHandler.canHandle(messageContext),
                "canHandle should return false when the event is null.");
    }

    @Test
    public void testCanHandleWithNullEventName() {

        Event event = mock(Event.class);
        when(event.getEventName()).thenReturn(null);
        IdentityEventMessageContext messageContext = mock(IdentityEventMessageContext.class);
        when(messageContext.getEvent()).thenReturn(event);
        assertFalse(registrationEventHookHandler.canHandle(messageContext),
                "canHandle should return false when event name is null.");
    }

    @Test
    public void testCanHandleForUserRegistrationFailedEvent() {

        Event event = new Event(IdentityEventConstants.Event.USER_REGISTRATION_FAILED);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        assertTrue(registrationEventHookHandler.canHandle(messageContext),
                "canHandle should return true for USER_REGISTRATION_FAILED event.");
    }

    @Test
    public void testCanHandleForPostAddNewPasswordInInviteFlow() {

        switchToFlow(new Flow.Builder().name(Flow.Name.INVITE).initiatingPersona(Flow.InitiatingPersona.ADMIN).build());
        try {
            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true for POST_ADD_NEW_PASSWORD in INVITE flow.");
        } finally {
            switchToFlow(new Flow.Builder().name(Flow.Name.REGISTER).initiatingPersona(Flow.InitiatingPersona.ADMIN).build());
        }
    }

    @Test
    public void testCanHandleForPostAddNewPasswordInNonInviteFlow() {

        Event event = createEventWithProperties(IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD);
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        // Current flow is REGISTER (set in setupClass), not INVITE.
        assertFalse(registrationEventHookHandler.canHandle(messageContext),
                "canHandle should return false for POST_ADD_NEW_PASSWORD in non-INVITE flow.");
    }

    @Test
    public void testCanHandleForSelfSignupConfirmInBulkUpdateFlow() {

        switchToFlow(new Flow.Builder().name(Flow.Name.BULK_RESOURCE_UPDATE).initiatingPersona(Flow.InitiatingPersona.ADMIN).build());
        try {
            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertFalse(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return false for POST_SELF_SIGNUP_CONFIRM in BULK_RESOURCE_UPDATE flow.");
        } finally {
            switchToFlow(new Flow.Builder().name(Flow.Name.REGISTER).initiatingPersona(Flow.InitiatingPersona.ADMIN).build());
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenSkipConfigDisabled() {

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("false");

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true when skip config is disabled in identity.xml.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenCompatibilitySettingDisabled() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            CompatibilitySetting compatibilitySetting = mock(CompatibilitySetting.class);
            CompatibilitySettingGroup settingGroup = mock(CompatibilitySettingGroup.class);
            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenReturn(compatibilitySetting);
            when(compatibilitySetting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP))
                    .thenReturn(settingGroup);
            when(settingGroup.getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING))
                    .thenReturn("false");

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true when compatibility setting is disabled.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenFlowConfigNull() throws Exception {

        // IdentityTenantUtil is already statically mocked from @BeforeClass; add the CARBON_SUPER stub directly.
        when(IdentityTenantUtil.getTenantId(CARBON_SUPER)).thenReturn(-1234);

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            CompatibilitySetting compatibilitySetting = mock(CompatibilitySetting.class);
            CompatibilitySettingGroup settingGroup = mock(CompatibilitySettingGroup.class);
            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenReturn(compatibilitySetting);
            when(compatibilitySetting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP))
                    .thenReturn(settingGroup);
            when(settingGroup.getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING))
                    .thenReturn("true");
            when(mockedFlowMgtService.getFlowConfig(FlowTypes.REGISTRATION.getType(), -1234)).thenReturn(null);

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true when flow config is null.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenFlowConfigDisabled() throws Exception {

        when(IdentityTenantUtil.getTenantId(CARBON_SUPER)).thenReturn(-1234);

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            CompatibilitySetting compatibilitySetting = mock(CompatibilitySetting.class);
            CompatibilitySettingGroup settingGroup = mock(CompatibilitySettingGroup.class);
            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenReturn(compatibilitySetting);
            when(compatibilitySetting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP))
                    .thenReturn(settingGroup);
            when(settingGroup.getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING))
                    .thenReturn("true");

            FlowConfigDTO flowConfig = mock(FlowConfigDTO.class);
            when(flowConfig.getIsEnabled()).thenReturn(false);
            when(mockedFlowMgtService.getFlowConfig(FlowTypes.REGISTRATION.getType(), -1234))
                    .thenReturn(flowConfig);

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true when registration flow config is disabled.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenAccountLockEnabled() throws Exception {

        when(IdentityTenantUtil.getTenantId(CARBON_SUPER)).thenReturn(-1234);

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            CompatibilitySetting compatibilitySetting = mock(CompatibilitySetting.class);
            CompatibilitySettingGroup settingGroup = mock(CompatibilitySettingGroup.class);
            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenReturn(compatibilitySetting);
            when(compatibilitySetting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP))
                    .thenReturn(settingGroup);
            when(settingGroup.getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING))
                    .thenReturn("true");

            FlowConfigDTO flowConfig = mock(FlowConfigDTO.class);
            when(flowConfig.getIsEnabled()).thenReturn(true);
            when(flowConfig.getFlowCompletionConfig(FlowCompletionConfig.IS_ACCOUNT_LOCK_ON_CREATION_ENABLED))
                    .thenReturn("true");
            when(mockedFlowMgtService.getFlowConfig(FlowTypes.REGISTRATION.getType(), -1234))
                    .thenReturn(flowConfig);

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true when account lock on creation is enabled in flow config.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenAccountLockDisabled() throws Exception {

        when(IdentityTenantUtil.getTenantId(CARBON_SUPER)).thenReturn(-1234);

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            CompatibilitySetting compatibilitySetting = mock(CompatibilitySetting.class);
            CompatibilitySettingGroup settingGroup = mock(CompatibilitySettingGroup.class);
            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenReturn(compatibilitySetting);
            when(compatibilitySetting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP))
                    .thenReturn(settingGroup);
            when(settingGroup.getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING))
                    .thenReturn("true");

            FlowConfigDTO flowConfig = mock(FlowConfigDTO.class);
            when(flowConfig.getIsEnabled()).thenReturn(true);
            when(flowConfig.getFlowCompletionConfig(FlowCompletionConfig.IS_ACCOUNT_LOCK_ON_CREATION_ENABLED))
                    .thenReturn("false");
            when(mockedFlowMgtService.getFlowConfig(FlowTypes.REGISTRATION.getType(), -1234))
                    .thenReturn(flowConfig);

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertFalse(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return false when account lock on creation is disabled: event should be skipped.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenTenantDomainMissing() {

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            HashMap<String, Object> properties = new HashMap<>();
            // Intentionally no TENANT_DOMAIN property.
            Event event = new Event(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM, properties);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true when tenant domain is missing (defaults to not skip).");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenCompatibilitySettingThrowsException() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenThrow(new RuntimeException("Service unavailable"));

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true (defaults to not skip) when compatibility setting lookup fails.");
        }
    }

    @Test
    public void testCanHandleForSelfSignupConfirmWhenFlowMgtServiceThrowsException() throws Exception {

        when(IdentityTenantUtil.getTenantId(CARBON_SUPER)).thenReturn(-1234);

        try (MockedStatic<IdentityUtil> identityUtilMocked = Mockito.mockStatic(IdentityUtil.class)) {
            identityUtilMocked.when(() -> IdentityUtil.getProperty(
                    Constants.SKIP_SIGNUP_CONFIRMATION_IF_ACCOUNT_LOCK_DISABLED)).thenReturn("true");

            CompatibilitySetting compatibilitySetting = mock(CompatibilitySetting.class);
            CompatibilitySettingGroup settingGroup = mock(CompatibilitySettingGroup.class);
            when(mockedCompatibilitySettingsService.getCompatibilitySettingsByGroupAndSetting(
                    eq(CARBON_SUPER),
                    eq(Constants.REGISTRATION_COMPAT_SETTING_GROUP),
                    eq(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING)))
                    .thenReturn(compatibilitySetting);
            when(compatibilitySetting.getCompatibilitySetting(Constants.REGISTRATION_COMPAT_SETTING_GROUP))
                    .thenReturn(settingGroup);
            when(settingGroup.getSettingValue(Constants.SKIP_SIGNUP_CONFIRMATION_COMPAT_SETTING))
                    .thenReturn("true");
            when(mockedFlowMgtService.getFlowConfig(FlowTypes.REGISTRATION.getType(), -1234))
                    .thenThrow(new RuntimeException("Flow service unavailable"));

            Event event = createEventWithProperties(IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM);
            IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
            assertTrue(registrationEventHookHandler.canHandle(messageContext),
                    "canHandle should return true (defaults to not skip) when flow management service fails.");
        }
    }
}
