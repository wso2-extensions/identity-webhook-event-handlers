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

package org.wso2.identity.webhook.common.event.handler;

import org.json.simple.JSONObject;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Attribute;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resources;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.config.ResourceConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.handler.SessionEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

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
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.SP_TO_CARBON_CLAIM_MAPPING;

/**
 * Unit tests for the SessionEventHookHandlerTest class and related classes.
 */
public class SessionEventHookHandlerTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER = "user";
    private static final String SAMPLE_EVENT_KEY_SESSION_REVOKED =
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    private static final String SAMPLE_EVENT_KEY_SESSION_ESTABLISHED =
            "https://schemas.openid.net/secevent/caep/event-type/session-established";
    private static final String SAMPLE_EVENT_KEY_SESSION_PRESENTED =
            "https://schemas.openid.net/secevent/caep/event-type/session-presented";
    private static final String SAMPLE_ATTRIBUTE_JSON = "{\"sendCredentials\":false,\"publishEnabled\":true}";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @InjectMocks
    private SessionEventHookHandler sessionEventHookHandler;
    @Mock
    private SessionEventPayloadBuilder mockedSessionEventPayloadBuilder;
    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;
    @Mock
    private EventConfigManager mockedEventConfigManager;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
    }

    @AfterMethod
    public void tearDownMethod() {

        Mockito.reset(mockedEventHookHandlerUtils);
        Mockito.reset(mockedEventPublisherService);
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][]{
                {IdentityEventConstants.EventName.USER_SESSION_TERMINATE.name(),
                        Constants.EventHandlerKey.CAEP.SESSION_REVOKED_EVENT,
                        SAMPLE_EVENT_KEY_SESSION_REVOKED
                },
                {IdentityEventConstants.EventName.SESSION_CREATE.name(),
                        Constants.EventHandlerKey.CAEP.SESSION_ESTABLISHED_EVENT,
                        SAMPLE_EVENT_KEY_SESSION_ESTABLISHED
                },
                {IdentityEventConstants.EventName.SESSION_UPDATE.name(),
                        Constants.EventHandlerKey.CAEP.SESSION_PRESENTED_EVENT,
                        SAMPLE_EVENT_KEY_SESSION_PRESENTED
                },
                {IdentityEventConstants.EventName.SESSION_EXTEND.name(),
                        Constants.EventHandlerKey.CAEP.SESSION_PRESENTED_EVENT,
                        SAMPLE_EVENT_KEY_SESSION_PRESENTED
                }
        };
    }

    @Test
    public void testGetName() {

        String expectedName = Constants.SESSION_EVENT_HOOK_NAME;
        String actualName = sessionEventHookHandler.getName();
        assertEquals(actualName, expectedName, "The name of the event hook handler should match.");
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String eventHandlerKey, String expectedEventKey)
            throws ConfigurationManagementException, IdentityEventException {

        Event event = createEventWithProperties(eventName);
        Resources resources = createResourcesWithAttributes(eventHandlerKey);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig(true,
                new ResourceConfig(new JSONObject()));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getSessionEventPayloadBuilder(EventSchema.CAEP))
                    .thenReturn(mockedSessionEventPayloadBuilder);
            when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);
            when(mockedEventConfigManager.getEventUri(anyString())).thenReturn(expectedEventKey);
            when(mockedEventConfigManager.extractEventPublisherConfig(any(Resources.class), anyString()))
                    .thenReturn(eventPublisherConfig);

            sessionEventHookHandler.handleEvent(event);

            verifyEventPublishedWithExpectedKey(expectedEventKey);
        }
    }

    @Test
    public void testHandleEventWithPublishingDisabled() throws
            ConfigurationManagementException, IdentityEventException {

        Event event = createEventWithProperties(IdentityEventConstants.EventName.USER_SESSION_TERMINATE.name());
        Resources resources = createResourcesWithAttributes(Constants.EventHandlerKey.CAEP.SESSION_REVOKED_EVENT);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig(false,
                new ResourceConfig(new JSONObject()));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getSessionEventPayloadBuilder(EventSchema.CAEP))
                    .thenReturn(mockedSessionEventPayloadBuilder);
            reset(mockedConfigurationManager);
            when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);
            when(mockedEventConfigManager.extractEventPublisherConfig(any(Resources.class), anyString()))
                    .thenReturn(eventPublisherConfig);

            sessionEventHookHandler.handleEvent(event);

            verify(mockedEventPublisherService, times(0)).publish(any(), any());
        }
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
    }

    private void setupPayloadBuilderMocks() throws IdentityEventException {

        when(mockedSessionEventPayloadBuilder.getEventSchemaType()).thenReturn(EventSchema.CAEP);
        when(mockedSessionEventPayloadBuilder.buildSessionUpdateEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedSessionEventPayloadBuilder.buildSessionExtendEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedSessionEventPayloadBuilder.buildSessionTerminateEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedSessionEventPayloadBuilder.buildSessionCreateEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedSessionEventPayloadBuilder.buildSessionExpireEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }

    private void setupUtilities() {

        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        sessionEventHookHandler = new SessionEventHookHandler(mockedEventConfigManager);
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        HashMap<String, Object> params = new HashMap<>();
        AuthenticationContext context = createAuthenticationContext();
        SessionContext sessionContext = createSessionContext();
        params.put("request", mock(HttpServletRequest.class));
        params.put("user", mockAuthenticatedUser());
        params.put("flow", mock(Flow.class));
        params.put("sessionData", "sample-sessionId");
        properties.put("context", context);
        properties.put("authenticationStatus", AuthenticatorStatus.PASS);
        properties.put("params", params);
        properties.put("sessionContext", sessionContext);

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

    private AuthenticationContext createAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        Map<String, String> sampleClaimMapping = new HashMap<>();
        sampleClaimMapping.put("roles", "http://wso2.org/claims/roles");
        sampleClaimMapping.put("default_tenant", "http://wso2.org/claims/runtime/default_tenant");
        sampleClaimMapping.put("active", "http://wso2.org/claims/active");
        sampleClaimMapping.put("preferred_username", "http://wso2.org/claims/displayName");
        sampleClaimMapping.put("given_name", "http://wso2.org/claims/givenname");
        sampleClaimMapping.put("family_name", "http://wso2.org/claims/lastname");
        sampleClaimMapping.put("email", "http://wso2.org/claims/emailaddress");
        sampleClaimMapping.put("username", "http://wso2.org/claims/username");
        sampleClaimMapping.put("associated_tenants", "http://wso2.org/claims/runtime/associated_tenants");
        context.setProperty(SP_TO_CARBON_CLAIM_MAPPING, sampleClaimMapping);
        return context;
    }

    private SessionContext createSessionContext() {

        SessionContext sessionContext = new SessionContext();
        sessionContext.addProperty("tenantDomain", SAMPLE_TENANT_DOMAIN);
        return sessionContext;
    }

    private AuthenticatedUser mockAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserName(SAMPLE_USER);
        user.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        user.setUserId("123");
        return user;
    }

    private void verifyEventPublishedWithExpectedKey(String expectedEventKey) {

        ArgumentCaptor<SecurityEventTokenPayload> argumentCaptor = ArgumentCaptor
                .forClass(SecurityEventTokenPayload.class);
        verify(mockedEventPublisherService, times(1)).publish(argumentCaptor.capture(),
                any(EventContext.class));

        SecurityEventTokenPayload capturedEventPayload = argumentCaptor.getValue();
        assertEquals(capturedEventPayload.getEvents().keySet().iterator().next(), expectedEventKey);
    }
}
