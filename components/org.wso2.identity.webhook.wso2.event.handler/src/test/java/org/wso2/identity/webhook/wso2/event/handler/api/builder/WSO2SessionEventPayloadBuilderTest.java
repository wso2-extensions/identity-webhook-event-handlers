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

package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.context.SessionContext;
import org.wso2.carbon.identity.application.authentication.framework.model.Application;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedIdPData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.UserSession;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

public class WSO2SessionEventPayloadBuilderTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER_NAME = "sampleUser";
    private static final String SAMPLE_USER_ID = "07f47397-2e77-4fce-9fac-41ff509d62de";
    private static final String SAMPLE_USERSTORE_NAME = "DEFAULT";
    private static final String SAMPLE_SERVICE_PROVIDER = "test-app";
    private static final String SAMPLE_IDP = "LOCAL";
    private static final String SAMPLE_AUTHENTICATOR = "sms-otp-authenticator";
    private static final String SAMPLE_SP_ID = "f27178f9-984b-41df-aee5-372de8ef327f";
    private static final int SAMPLE_TENANT_ID = 100;
    private static final String SAMPLE_ERROR_CODE = "SMS-65020";

    @Mock
    private EventData mockEventData;

    @Mock
    private OrganizationManager mockOrganizationManager;

    @InjectMocks
    private WSO2SessionEventPayloadBuilder payloadBuilder;

    @Mock
    private AuthenticationContext mockAuthenticationContext;

    @Mock
    private AuthenticatedUser mockAuthenticatedUser;

    @Mock
    private SessionContext mockSessionContext;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    @Mock
    private UserSessionManagementService userSessionManagementService;

    private MockedStatic<FrameworkUtils> frameworkUtilsMockedStatic;

    @BeforeClass
    public void setup() throws Exception {

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
        WSO2EventHookHandlerDataHolder.getInstance().setUserSessionManagementService(userSessionManagementService);

        mockAuthenticationContext = createMockAuthenticationContext();
        mockAuthenticatedUser = createMockAuthenticatedUser();
        mockSessionContext = createMockSessionContext();

        frameworkUtilsMockedStatic = mockStatic(FrameworkUtils.class);
        frameworkUtilsMockedStatic.when(() -> FrameworkUtils.getMultiAttributeSeparator()).thenReturn(",");
        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        CommonTestUtils.initPrivilegedCarbonContext(SAMPLE_TENANT_DOMAIN, SAMPLE_TENANT_ID, SAMPLE_USER_NAME);
    }

    @AfterClass
    public void teardown() {

        frameworkUtilsMockedStatic.close();
        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();

        Mockito.reset(claimMetadataManagementService);
    }

    @Test
    public void testGetEventSchema() {

        EventSchema schema = payloadBuilder.getEventSchemaType();
        assertEquals(schema, EventSchema.WSO2);
    }

    @DataProvider(name = "revokedEventDataProvider")
    public Object[][] revokedEventDataProvider() {

        List<UserSession> sessions = new ArrayList<>();
        UserSession session1 = getUserSession("sessionId1", "Sample1", "SampleApp1", "1");
        sessions.add(session1);
        UserSession session2 = getUserSession("sessionId2", "Sample2", "SampleApp2", "2");
        sessions.add(session2);

        return new Object[][]{
                {Flow.InitiatingPersona.ADMIN, sessions},
                {Flow.InitiatingPersona.USER, sessions},
                {Flow.InitiatingPersona.APPLICATION, null},
                {Flow.InitiatingPersona.SYSTEM, sessions.subList(0, 1)}
        };
    }

    private UserSession getUserSession(String id, String applicationSample, String applicationName,
                                       String applicationId) {

        UserSession session1 = new UserSession();
        session1.setSessionId(id);
        Application app = new Application(applicationSample, applicationName, applicationId);
        session1.setApplications(Collections.singletonList(app));
        return session1;
    }

    @Test(dataProvider = "revokedEventDataProvider")
    public void testBuildSessionTerminateEvent
            (Flow.InitiatingPersona initiatingEntity, List<UserSession> sessions)
            throws IdentityEventException {

        Map<String, Object> params = new HashMap<>();
        params.put("sessions", sessions);
        params.put("eventTimeStamp", System.currentTimeMillis());

        EventData eventData = new EventData.Builder()
                .eventName(IdentityEventConstants.Event.SESSION_TERMINATE_V2)
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(null)
                .sessionContext(null)
                .eventParams(params)
                .tenantDomain(SAMPLE_TENANT_DOMAIN)
                .userId(SAMPLE_USER_ID)
                .build();

        EventPayload payload = payloadBuilder.buildSessionTerminateEvent(eventData);
        assertTrue(payload instanceof WSO2SessionRevokedEventPayload);

        WSO2SessionRevokedEventPayload sessionRevokedPayload =
                (WSO2SessionRevokedEventPayload) payload;

        assertEquals(sessionRevokedPayload.getUser().getId(), SAMPLE_USER_ID);
        assertEquals(sessionRevokedPayload.getUserStore().getName(), SAMPLE_USERSTORE_NAME);
        assertEquals(sessionRevokedPayload.getTenant().getId(), String.valueOf(SAMPLE_TENANT_ID));
        assertEquals(sessionRevokedPayload.getTenant().getName(), SAMPLE_TENANT_DOMAIN);
    }

    @Test
    public void testSessionCreateEvent() throws IdentityEventException {

        Map<String, Object> params = new HashMap<>();
        params.put("eventTimeStamp", System.currentTimeMillis());
        params.put("sessionId", "sessionId");

        EventData eventData = new EventData.Builder()
                .eventName("SESSION_CREATE")
                .authenticatedUser(mockAuthenticatedUser)
                .authenticationContext(mockAuthenticationContext)
                .sessionContext(mockSessionContext)
                .tenantDomain(SAMPLE_TENANT_DOMAIN)
                .eventParams(params)
                .build();

        EventPayload payload = payloadBuilder.buildSessionCreateEvent(eventData);
        assertTrue(payload instanceof WSO2SessionCreatedEventPayload);

        WSO2SessionCreatedEventPayload sessionCreatePayload =
                (WSO2SessionCreatedEventPayload) payload;

        assertEquals(sessionCreatePayload.getUser().getId(), SAMPLE_USER_ID);
        assertEquals(sessionCreatePayload.getUserStore().getName(), SAMPLE_USERSTORE_NAME);
        assertEquals(sessionCreatePayload.getTenant().getId(), String.valueOf(SAMPLE_TENANT_ID));
        assertEquals(sessionCreatePayload.getTenant().getName(), SAMPLE_TENANT_DOMAIN);
    }

    @Test
    public void testSessionUpdateEvent() throws IdentityEventException {

        EventPayload payload = payloadBuilder.buildSessionUpdateEvent(mockEventData);
        assertNull(payload);
    }

    @Test
    public void testSessionExtend() throws IdentityEventException {

        EventPayload payload = payloadBuilder.buildSessionExtendEvent(mockEventData);
        assertNull(payload);
    }

    @Test
    public void testSessionExpire() throws IdentityEventException {

        EventPayload payload = payloadBuilder.buildSessionExpireEvent(mockEventData);
        assertNull(payload);
    }

    private SessionContext createMockSessionContext() {

        SessionContext sessionContext = new SessionContext();
        Map<String, Map<String, AuthenticatedIdPData>> authenticatedIdPsOfApp = new HashMap<>();
        authenticatedIdPsOfApp.put("SampleApp", new HashMap<>());
        authenticatedIdPsOfApp.put("SampleApp2", new HashMap<>());
        sessionContext.setAuthenticatedIdPsOfApp(Collections.unmodifiableMap(authenticatedIdPsOfApp));
        return sessionContext;
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

        HashMap<String, String> dataMap = new HashMap<>();
        dataMap.put(Constants.CURRENT_AUTHENTICATOR_ERROR_CODE, SAMPLE_ERROR_CODE);
        context.setProperty(Constants.DATA_MAP, dataMap);

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
        user.setUserAttributes(getMockUserAttributes());
        return user;
    }

    private Map<ClaimMapping, String> getMockUserAttributes() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        Claim usernameClaim = new Claim();
        usernameClaim.setClaimUri("http://wso2.org/claims/username");
        ClaimMapping usernameClaimMapping = new ClaimMapping();
        usernameClaimMapping.setLocalClaim(usernameClaim);
        userAttributes.put(usernameClaimMapping, SAMPLE_USER_NAME);

        Claim emailClaim = new Claim();
        emailClaim.setClaimUri("http://wso2.org/claims/emailaddress");
        ClaimMapping emailClaimMapping = new ClaimMapping();
        emailClaimMapping.setLocalClaim(emailClaim);
        userAttributes.put(emailClaimMapping, "sample@wso2.com");

        return userAttributes;
    }
}
