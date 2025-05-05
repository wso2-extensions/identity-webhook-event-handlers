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

package org.wso2.identity.webhook.caep.event.handler;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.caep.event.handler.api.builder.CAEPSessionEventPayloadBuilder;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionEstablishedAndPresentedEventPayload;
import org.wso2.identity.webhook.caep.event.handler.internal.model.CAEPSessionRevokedEventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.caep.event.handler.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit test class for {@link CAEPSessionEventPayloadBuilder}.
 */
public class CAEPSessionEventPayloadBuilderTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER_NAME = "sampleUser";
    private static final String SAMPLE_USER_ID = "07f47397-2e77-4fce-9fac-41ff509d62de";
    private static final String SAMPLE_USERSTORE_NAME = "DEFAULT";
    private static final String SAMPLE_SERVICE_PROVIDER = "test-app";
    private static final String SAMPLE_IDP = "LOCAL";
    private static final String SAMPLE_AUTHENTICATOR = "sms-otp-authenticator";
    private static final String SAMPLE_SP_ID = "f27178f9-984b-41df-aee5-372de8ef327f";

    @InjectMocks
    private CAEPSessionEventPayloadBuilder caepSessionEventPayloadBuilder;

    @Mock
    private EventData mockEventData;

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private AuthenticatedUser mockAuthenticatedUser;

    @BeforeClass
    public void setup() {

        MockitoAnnotations.openMocks(this);
        mockAuthenticationContext = createMockAuthenticationContext();
        mockAuthenticatedUser = createMockAuthenticatedUser();
        mockServiceURLBuilder();
        mockIdentityTenantUtil();
    }

    @AfterClass
    public void teardown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
    }

    @Test
    public void testGetEventSchemaType() {

        EventSchema eventSchema = caepSessionEventPayloadBuilder.getEventSchemaType();

        assertNotNull(eventSchema, "Event schema should not be null");
        assertEquals(eventSchema, EventSchema.CAEP, "Event schema should be CAEP");
    }

    @Test
    public void testBuildSessionTerminateEvent() throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);
        Map<String, Object> paramMap = new HashMap<>();
        paramMap.put("eventTimestamp", System.currentTimeMillis());
        when(mockEventData.getEventParams()).thenReturn(paramMap);

        CAEPSessionRevokedEventPayload eventPayload = (CAEPSessionRevokedEventPayload)
                caepSessionEventPayloadBuilder.buildSessionTerminateEvent(mockEventData);

        assertNotNull(eventPayload, "Event payload should not be null");
        assertTrue(eventPayload.getEventTimeStamp() > 0, "Event timestamp should be greater than 0");

    }

    @Test
    public void testSessionTerminationByLogout() throws IdentityEventException {

        mockAuthenticationContext.setLogoutRequest(true);
        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);
        Map<String, Object> paramMap = new HashMap<>();
        when(mockEventData.getEventParams()).thenReturn(paramMap);

        CAEPSessionRevokedEventPayload eventPayload = (CAEPSessionRevokedEventPayload)
                caepSessionEventPayloadBuilder.buildSessionTerminateEvent(mockEventData);

        assertNotNull(eventPayload, "Event payload should not be null");
        assertEquals("User logout", eventPayload.getReasonAdmin().get("en"));
        assertEquals("User Logged out", eventPayload.getReasonUser().get("en"));
        assertEquals("user", eventPayload.getInitiatingEntity());
        assertTrue(eventPayload.getEventTimeStamp() > 0, "Event timestamp should be greater than 0");

        mockAuthenticationContext.setLogoutRequest(false);

    }

    @Test
    public void testBuildSessionExpireEvent() throws IdentityEventException {

        EventPayload eventPayload = caepSessionEventPayloadBuilder.buildSessionExpireEvent(mockEventData);

        assertNull(eventPayload, "Event payload should be null");
    }

    @Test
    public void testBuildSessionExtendEvent() throws IdentityEventException {

        EventPayload eventPayload = caepSessionEventPayloadBuilder.buildSessionExtendEvent(mockEventData);

        assertNull(eventPayload, "Event payload should be null");
    }

    @Test
    public void testBuildSessionUpdateEvent() throws IdentityEventException {

        long systemTime = System.currentTimeMillis();
        SessionContext mockSessionContext = mock(SessionContext.class);
        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);
        when(mockSessionContext.getProperty("UpdatedTimestamp")).thenReturn(systemTime);
        when(mockEventData.getSessionContext()).thenReturn(mockSessionContext);

        CAEPSessionEstablishedAndPresentedEventPayload eventPayload =
                (CAEPSessionEstablishedAndPresentedEventPayload) caepSessionEventPayloadBuilder
                        .buildSessionUpdateEvent(mockEventData);

        assertNotNull(eventPayload, "Event payload should not be null");
        assertEquals(eventPayload.getEventTimeStamp(), systemTime, "Event timestamp should match");

    }

    @Test
    public void testBuildSessionCreateEvent() throws IdentityEventException {

        long systemTime = System.currentTimeMillis();
        SessionContext mockSessionContext = mock(SessionContext.class);
        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);
        when(mockSessionContext.getProperty("CreatedTimestamp")).thenReturn(systemTime);
        when(mockEventData.getSessionContext()).thenReturn(mockSessionContext);

        CAEPSessionEstablishedAndPresentedEventPayload eventPayload =
                (CAEPSessionEstablishedAndPresentedEventPayload) caepSessionEventPayloadBuilder
                        .buildSessionCreateEvent(mockEventData);

        assertNotNull(eventPayload, "Event payload should not be null");
        assertEquals(eventPayload.getEventTimeStamp(), systemTime, "Event timestamp should match");
    }

    private AuthenticationContext createMockAuthenticationContext() {

        AuthenticationContext context = new AuthenticationContext();
        context.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        context.setLoginTenantDomain(SAMPLE_TENANT_DOMAIN);
        context.setServiceProviderName(SAMPLE_SERVICE_PROVIDER);
        context.setServiceProviderResourceId(SAMPLE_SP_ID);
        AuthHistory step = new AuthHistory(SAMPLE_AUTHENTICATOR, SAMPLE_IDP);
        context.addAuthenticationStepHistory(step);
        context.setCurrentStep(2);
        context.setCurrentAuthenticator(SAMPLE_AUTHENTICATOR);

        IdentityProvider localIdP = new IdentityProvider();
        localIdP.setIdentityProviderName(SAMPLE_IDP);
        ExternalIdPConfig localIdPConfig = new ExternalIdPConfig(localIdP);
        context.setExternalIdP(localIdPConfig);

        AuthenticatedUser authenticatedUser = createMockAuthenticatedUser();
        context.setSubject(authenticatedUser);

        return context;
    }

    private AuthenticatedUser createMockAuthenticatedUser() {

        AuthenticatedUser user = new AuthenticatedUser();
        user.setUserId(SAMPLE_USER_ID);
        user.setUserStoreDomain(SAMPLE_USERSTORE_NAME);
        user.setTenantDomain(SAMPLE_TENANT_DOMAIN);
        user.setFederatedUser(false);
        user.setAuthenticatedSubjectIdentifier(SAMPLE_USER_NAME);
        user.setUserName(SAMPLE_USER_NAME);
        return user;
    }
}
