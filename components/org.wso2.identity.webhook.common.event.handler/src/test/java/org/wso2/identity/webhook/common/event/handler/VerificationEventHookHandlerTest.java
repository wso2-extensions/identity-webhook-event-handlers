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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
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
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.VerificationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.config.ResourceConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.handler.VerificationEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.ArrayList;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Answers.CALLS_REAL_METHODS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

public class VerificationEventHookHandlerTest {

    private static final String SAMPLE_EVENT_KEY_VERIFICATION =
            "https://schemas.openid.net/secevent/caep/event-type/verification";
    private static final String SAMPLE_STREAM_ID = "23fqa3-2fawq30-ag234";
    private static final String SAMPLE_STATE = "ani23fao10fao201a1fano";
    private static final String SAMPLE_ATTRIBUTE_JSON = "{\"sendCredentials\":false,\"publishEnabled\":true}";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @InjectMocks
    private VerificationEventHookHandler verificationEventHookHandler;

    @Mock
    private EventConfigManager mockedEventConfigManager;

    @Mock
    private VerificationEventPayloadBuilder mockedVerificationEventPayloadBuilder;

    @Mock
    private EventHookHandlerUtils mockedEventHookHandlerUtils;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        setupDataHolderMocks();
        setupPayloadBuilderMocks();
        setupUtilities();
    }

    @Test
    public void testCanHandle() {

        Event event = new Event("VERIFICATION");
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);
        boolean canHandle = verificationEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle, "The event handler should be able to handle the event.");

        event = new Event(IdentityEventConstants.EventName.AUTHENTICATION_FAILURE.name());
        messageContext = new IdentityEventMessageContext(event);
        canHandle = verificationEventHookHandler.canHandle(messageContext);
        assertFalse(canHandle, "Handler should not handle AUTHENTICATION_FAILURE event.");
    }

    @Test
    public void testGetName() {

        String expectedName = Constants.VERIFICATION_EVENT_HOOK_NAME;
        String actualName = verificationEventHookHandler.getName();
        assertEquals(actualName, expectedName, "The name of the event hook handler should match.");
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][]{{
                "VERIFICATION", Constants.EventHandlerKey.CAEP.VERIFICATION_EVENT,
                SAMPLE_EVENT_KEY_VERIFICATION}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String eventHandlerKey, String expectedEventKey) throws
            ConfigurationManagementException, IdentityEventException {

        Event event = createEventWithProperties(eventName);
        Resources resources = createResourcesWithAttributes(eventHandlerKey);
        EventPublisherConfig eventPublisherConfig = new EventPublisherConfig(true,
                new ResourceConfig(new JSONObject()));

        try (MockedStatic<PayloadBuilderFactory> mocked = mockStatic(PayloadBuilderFactory.class)) {
            mocked.when(() -> PayloadBuilderFactory.getVerificationEventPayloadBuilder(EventSchema.CAEP)).
                    thenReturn(mockedVerificationEventPayloadBuilder);
            when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);
            when(mockedEventConfigManager.getEventUri(anyString())).thenReturn(expectedEventKey);
            when(mockedEventConfigManager.extractEventPublisherConfig(any(Resources.class), anyString())).
                    thenReturn(eventPublisherConfig);

            verificationEventHookHandler.handleEvent(event);
        }
    }

    private Event createEventWithProperties(String eventName) {

        HashMap<String, Object> properties = new HashMap<>();
        HashMap<String, Object> params = new HashMap<>();
        AuthenticatedUser authenticatedUser = mock(AuthenticatedUser.class);
        when(authenticatedUser.getTenantDomain()).thenReturn("sample-domain");
        params.put("request", mock(HttpServletRequest.class));
        params.put("user", authenticatedUser);
        params.put("streamId", SAMPLE_STREAM_ID);
        params.put("state", SAMPLE_STATE);
        properties.put("context", mock(AuthenticationContext.class));
        properties.put("authenticationStatus", AuthenticatorStatus.PASS);
        properties.put("params", params);
        properties.put("sessionContext", mock(SessionContext.class));

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

    private void setupUtilities() {

        mockedEventHookHandlerUtils = mock(EventHookHandlerUtils.class, withSettings()
                .defaultAnswer(CALLS_REAL_METHODS));
        verificationEventHookHandler = new VerificationEventHookHandler(mockedEventConfigManager);
    }

    private void setupDataHolderMocks() {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);
    }

    private void setupPayloadBuilderMocks() {

        when(mockedVerificationEventPayloadBuilder.getEventSchemaType()).thenReturn(EventSchema.CAEP);
        when(mockedVerificationEventPayloadBuilder.buildVerificationEventPayload(any(EventData.class)))
                .thenReturn(mockedEventPayload);
    }
}
