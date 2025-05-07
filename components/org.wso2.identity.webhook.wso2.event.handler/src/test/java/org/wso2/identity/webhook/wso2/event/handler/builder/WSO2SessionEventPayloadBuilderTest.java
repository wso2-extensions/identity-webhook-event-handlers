package org.wso2.identity.webhook.wso2.event.handler.builder;

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
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2SessionEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2SessionRevokedEventPayload;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.builder.util.TestUtils.mockServiceURLBuilder;

public class WSO2SessionEventPayloadBuilderTest {

    private static final String SAMPLE_TENANT_DOMAIN = "myorg";
    private static final String SAMPLE_USER_NAME = "sampleUser";
    private static final String SAMPLE_USER_ID = "07f47397-2e77-4fce-9fac-41ff509d62de";
    private static final String SAMPLE_USERSTORE_NAME = "DEFAULT";
    private static final String SAMPLE_SERVICE_PROVIDER = "test-app";
    private static final String SAMPLE_IDP = "LOCAL";
    private static final String SAMPLE_AUTHENTICATOR = "sms-otp-authenticator";
    private static final String SAMPLE_SP_ID = "f27178f9-984b-41df-aee5-372de8ef327f";
    private static final String SAMPLE_TENANT_ID = "100";
    private static final String SAMPLE_USER_REF = "https://localhost:9443/t/myorg/scim2/" + SAMPLE_USER_ID;
    private static final String SAMPLE_ERROR_CODE = "SMS-65020";

    @Mock
    private EventData mockEventData;

    @Mock
    private OrganizationManager mockOrganizationManager;

    @Mock
    private WSO2SessionEventPayloadBuilder payloadBuilder;

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

    @DataProvider(name = "revokedEventDataProvider")
    public Object[][] revokedEventDataProvider() {

        return new Object[][]{
                {SAMPLE_USER_ID, SAMPLE_USERSTORE_NAME, SAMPLE_SP_ID, SAMPLE_SERVICE_PROVIDER, SAMPLE_TENANT_ID,
                        SAMPLE_TENANT_DOMAIN}
        };
    }

    @Test(dataProvider = "revokedEventDataProvider")
    public void testBuildSessionTerminateEvent(String userId, String userStoreDomain, String appId, String appName,
                                               String tenantId, String tenantDomain) throws Exception {

        when(mockEventData.getAuthenticationContext()).thenReturn(mockAuthenticationContext);
        when(mockEventData.getAuthenticatedUser()).thenReturn(mockAuthenticatedUser);

        EventPayload payload = payloadBuilder.buildSessionTerminateEvent(mockEventData);
        assertTrue(payload instanceof WSO2SessionRevokedEventPayload);

        WSO2SessionRevokedEventPayload sessionRevokedPayload =
                (WSO2SessionRevokedEventPayload) payload;

        assertEquals(userId, sessionRevokedPayload.getUser().getId());
        assertEquals(userStoreDomain, sessionRevokedPayload.getUserStore());
        assertEquals(tenantId, sessionRevokedPayload.getTenant().getId());
        assertEquals(tenantDomain, sessionRevokedPayload.getTenant().getName());

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

