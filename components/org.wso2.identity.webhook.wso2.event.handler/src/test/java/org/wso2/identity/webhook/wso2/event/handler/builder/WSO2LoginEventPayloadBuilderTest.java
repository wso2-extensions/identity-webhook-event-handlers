/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.builder;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2LoginEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.AuthenticationFailedStep;
import org.wso2.identity.webhook.wso2.event.handler.internal.service.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationSuccessEventPayload;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.mockServiceURLBuilder;

/**
 * Test class for WSO2LoginEventPayloadBuilder.
 */
public class WSO2LoginEventPayloadBuilderTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER_NAME = "sampleUser";
    private static final String SAMPLE_USER_ID = "07f47397-2e77-4fce-9fac-41ff509d62de";
    private static final String SAMPLE_USERSTORE_NAME = "DEFAULT";
    private static final String SAMPLE_SERVICE_PROVIDER = "test-app";
    private static final String SAMPLE_IDP = "LOCAL";
    private static final String SAMPLE_MESSAGE = "Invalid Credentials";
    private static final String SAMPLE_AUTHENTICATOR = "sms-otp-authenticator";
    private static final String SAMPLE_SP_ID = "f27178f9-984b-41df-aee5-372de8ef327f";
    private static final String SAMPLE_TENANT_ID = "100";
    private static final String SAMPLE_USER_REF = "https://localhost:9443/t/myorg/scim2/" + SAMPLE_USER_ID;
    private static final String SAMPLE_ERROR_CODE = "SMS-65020";

    @Mock
    private EventData mockEventData;

    @Mock
    private OrganizationManager mockOrganizationManager;

    @InjectMocks
    private WSO2LoginEventPayloadBuilder payloadBuilder;

    @Mock
    private AuthenticationContext mockAuthenticationContext;
    @Mock
    private AuthenticatedUser mockAuthenticatedUser;

    @BeforeClass
    public void setup() {

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(mockOrganizationManager);
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

    @DataProvider(name = "successEventDataProvider")
    public Object[][] successEventDataProvider() {

        return new Object[][] {
                {SAMPLE_USER_ID, SAMPLE_USERSTORE_NAME, SAMPLE_SP_ID, SAMPLE_SERVICE_PROVIDER, SAMPLE_TENANT_ID,
                        SAMPLE_TENANT_DOMAIN, SAMPLE_USER_REF, 1}
        };
    }

    @Test(dataProvider = "successEventDataProvider")
    public void testBuildAuthenticationSuccessEvent(String userId, String userStore, String appId, String appName,
                                                    String tenantId, String tenantName, String userRef,
                                                    int authMethodsSize) throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);

        EventPayload eventPayload = payloadBuilder.buildAuthenticationSuccessEvent(mockEventData);
        assertTrue(eventPayload instanceof WSO2AuthenticationSuccessEventPayload);

        WSO2AuthenticationSuccessEventPayload successPayload = (WSO2AuthenticationSuccessEventPayload) eventPayload;

        assertEquals(successPayload.getUser().getId(), userId);
        assertEquals(successPayload.getUserStore().getName(), userStore);
        assertEquals(successPayload.getApplication().getId(), appId);
        assertEquals(successPayload.getApplication().getName(), appName);
        assertEquals(successPayload.getTenant().getId(), tenantId);
        assertEquals(successPayload.getTenant().getName(), tenantName);
        assertEquals(successPayload.getUser().getRef(), userRef);
        assertEquals(successPayload.getAuthenticationMethods().size(), authMethodsSize);
    }

    @Test(expectedExceptions = IdentityEventException.class)
    public void testBuildAuthenticationSuccessEventWithNullUser() throws IdentityEventException {

        when(mockEventData.getAuthenticatedUser()).thenReturn(null);
        payloadBuilder.buildAuthenticationSuccessEvent(mockEventData);
    }

    @DataProvider(name = "failedEventDataProvider")
    public Object[][] failedEventDataProvider() {

        return new Object[][] {
                {SAMPLE_USER_ID, SAMPLE_USERSTORE_NAME, SAMPLE_SP_ID, SAMPLE_SERVICE_PROVIDER, SAMPLE_TENANT_ID,
                        SAMPLE_TENANT_DOMAIN, SAMPLE_USER_REF, SAMPLE_ERROR_CODE, 2, SAMPLE_MESSAGE, SAMPLE_IDP, SAMPLE_AUTHENTICATOR}
        };
    }

    @Test(dataProvider = "failedEventDataProvider")
    public void testBuildAuthenticationFailedEvent(String userId, String userStore, String appId, String appName,
                                                   String tenantId, String tenantName, String userRef, String reasonId,
                                                   String reasonMessage, int failedStep, String idp,
                                                   String authenticator) throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        mockAuthenticationContext.setSubject(mockAuthenticatedUser);

        EventPayload eventPayload = payloadBuilder.buildAuthenticationFailedEvent(mockEventData);
        assertTrue(eventPayload instanceof WSO2AuthenticationFailedEventPayload);

        WSO2AuthenticationFailedEventPayload failedPayload = (WSO2AuthenticationFailedEventPayload) eventPayload;

        assertEquals(failedPayload.getUser().getId(), userId);
        assertEquals(failedPayload.getUserStore().getName(), userStore);
        assertEquals(failedPayload.getApplication().getId(), appId);
        assertEquals(failedPayload.getApplication().getName(), appName);
        assertEquals(failedPayload.getTenant().getId(), tenantId);
        assertEquals(failedPayload.getTenant().getName(), tenantName);
        assertEquals(failedPayload.getUser().getRef(), userRef);
        assertEquals(failedPayload.getReason().getId(), reasonId);
        assertEquals(failedPayload.getReason().getMessage(), reasonMessage);
        assertEquals(((AuthenticationFailedStep) failedPayload.getReason().getContext().get("failedStep")).getStep(), failedStep);
        assertEquals(((AuthenticationFailedStep) failedPayload.getReason().getContext().get("failedStep")).getIdp(), idp);
        assertEquals(((AuthenticationFailedStep) failedPayload.getReason().getContext().get("failedStep")).getAuthenticator(), authenticator);
    }

    @Test
    public void testBuildAuthenticationFailedEventWithNullUser() throws IdentityEventException {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        mockAuthenticationContext.setSubject(null);

        EventPayload eventPayload = payloadBuilder.buildAuthenticationFailedEvent(mockEventData);
        assertTrue(eventPayload instanceof WSO2AuthenticationFailedEventPayload);

        WSO2AuthenticationFailedEventPayload failedPayload = (WSO2AuthenticationFailedEventPayload) eventPayload;

        assertEquals(failedPayload.getApplication().getId(), SAMPLE_SP_ID);
        assertEquals(failedPayload.getApplication().getName(), SAMPLE_SERVICE_PROVIDER);
        assertEquals(failedPayload.getTenant().getId(), SAMPLE_TENANT_ID);
        assertEquals(failedPayload.getTenant().getName(), SAMPLE_TENANT_DOMAIN);
        assertEquals(failedPayload.getReason().getId(), SAMPLE_ERROR_CODE);
        assertEquals(((AuthenticationFailedStep) failedPayload.getReason().getContext().get("failedStep")).getStep(), 2);
        assertEquals(((AuthenticationFailedStep) failedPayload.getReason().getContext().get("failedStep")).getIdp(), SAMPLE_IDP);
        assertEquals(((AuthenticationFailedStep) failedPayload.getReason().getContext().get("failedStep")).getAuthenticator(), SAMPLE_AUTHENTICATOR);
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
