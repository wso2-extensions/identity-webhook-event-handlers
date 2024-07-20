/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import org.json.simple.parser.ParseException;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
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
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.model.EventAttribute;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.common.event.handler.model.ResourceConfig;
import org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.util.TestUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_CONFIG_SCHEMA_NAME_KEY;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.common.event.handler.util.TestUtils.mockServiceURLBuilder;

public class LoginEventHookHandlerTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER = "user";
    private static final String SAMPLE_EVENT_KEY_LOGIN_SUCCESS = "schemas.identity.wso2.org/events/logins/event-type/loginSuccess";
    private static final String SAMPLE_EVENT_KEY_LOGIN_FAILED = "schemas.identity.wso2.org/events/logins/event-type/loginFailed";
    private static final String SAMPLE_ATTRIBUTE_JSON = "{\"sendCredentials\":false,\"publishEnabled\":true}";

    @Mock
    private ConfigurationManager mockedConfigurationManager;
    @Mock
    private EventPublisherService mockedEventPublisherService;
    @Mock
    private EventPayload mockedEventPayload;
    @InjectMocks
    private LoginEventHookHandler loginEventHookHandler;
    @Mock
    private LoginEventPayloadBuilder mockedLoginEventPayloadBuilder;
    private static MockedStatic<PayloadBuilderFactory> mockedPayloadBuilderFactory;

    @BeforeClass
    public void setupClass() throws IdentityEventException {

        MockitoAnnotations.openMocks(this);
        EventHookHandlerDataHolder.getInstance().setConfigurationManager(mockedConfigurationManager);
        EventHookHandlerDataHolder.getInstance().setEventPublisherService(mockedEventPublisherService);

        mockedPayloadBuilderFactory = mockStatic(PayloadBuilderFactory.class);

        // Register the mocked LoginEventPayloadBuilder for the WSO2 schema
        when(mockedLoginEventPayloadBuilder.getEventSchemaType()).thenReturn("WSO2");
        mockedPayloadBuilderFactory.when(() -> PayloadBuilderFactory.getLoginEventPayloadBuilder(anyString()))
                .thenReturn(mockedLoginEventPayloadBuilder);

        // Mock the buildAuthenticationSuccessEvent and buildAuthenticationFailedEvent methods
        when(mockedLoginEventPayloadBuilder.buildAuthenticationSuccessEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        when(mockedLoginEventPayloadBuilder.buildAuthenticationFailedEvent(any(EventData.class)))
                .thenReturn(mockedEventPayload);
        mockServiceURLBuilder();
        mockIdentityTenantUtil();
    }

    @AfterMethod
    public void tearDownMethod() {

        reset(mockedEventPublisherService);
    }

    @AfterClass
    public void tearDownClass() {

        mockedPayloadBuilderFactory.close();
    }

    @Test
    public void testCanHandle() {

        Event event = new Event(IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name());
        IdentityEventMessageContext messageContext = new IdentityEventMessageContext(event);

        boolean canHandle = loginEventHookHandler.canHandle(messageContext);
        assertTrue(canHandle, "The event handler should be able to handle the event.");
    }

    @DataProvider(name = "eventDataProvider")
    public Object[][] eventDataProvider() {

        return new Object[][] {
                {IdentityEventConstants.EventName.AUTHENTICATION_SUCCESS.name(), Constants.EventHandlerKey.LOGIN_SUCCESS_EVENT, SAMPLE_EVENT_KEY_LOGIN_SUCCESS},
                {IdentityEventConstants.EventName.AUTHENTICATION_STEP_FAILURE.name(), Constants.EventHandlerKey.LOGIN_FAILED_EVENT, SAMPLE_EVENT_KEY_LOGIN_FAILED}
        };
    }

    @Test(dataProvider = "eventDataProvider")
    public void testHandleEvent(String eventName, String eventHandlerKey, String expectedEventKey)
            throws ConfigurationManagementException, IdentityEventException,
            IOException, ParseException {

        HashMap<String, Object> properties = new HashMap<>();
        HashMap<String, Object> params = new HashMap<>();
        AuthenticationContext context = createAuthenticationContext();
        params.put(SAMPLE_USER, context.getSubject());
        properties.put(IdentityEventConstants.EventProperty.CONTEXT, context);
        properties.put(IdentityEventConstants.EventProperty.AUTHENTICATION_STATUS, AuthenticatorStatus.PASS);
        properties.put(IdentityEventConstants.EventProperty.PARAMS, params);

        Event event = new Event(eventName, properties);

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
        when(mockedConfigurationManager.getTenantResources(anyString(), any())).thenReturn(resources);

        org.json.simple.JSONObject eventConfig = (org.json.simple.JSONObject) TestUtils.getEventSchemas()
                .get(eventHandlerKey);
        String eventSchemaUri = (String) eventConfig.get(EVENT_CONFIG_SCHEMA_NAME_KEY);
        when(EventHookHandlerUtils.getEventConfig(eventHandlerKey))
                .thenReturn(new ResourceConfig(eventConfig));

        EventAttribute eventAttribute = new EventAttribute(
                true, new ResourceConfig(new org.json.simple.JSONObject()));
        when(EventHookHandlerUtils.buildEventAttributeFromJSONString(anyString())).thenReturn(eventAttribute);

        loginEventHookHandler.handleEvent(event);

        ArgumentCaptor<SecurityEventTokenPayload> argumentCaptor = ArgumentCaptor.forClass(SecurityEventTokenPayload.class);
        verify(mockedEventPublisherService).publish(argumentCaptor.capture(), any(EventContext.class));

        SecurityEventTokenPayload capturedEventPayload = argumentCaptor.getValue();
        assertEquals(capturedEventPayload.getEvent().keySet().iterator().next(), expectedEventKey);
    }

    private AuthenticationContext createAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        return context;
    }
}
