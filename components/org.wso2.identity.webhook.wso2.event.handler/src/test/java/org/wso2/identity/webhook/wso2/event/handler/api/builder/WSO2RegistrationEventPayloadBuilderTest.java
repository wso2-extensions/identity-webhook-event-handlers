package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.config.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2BaseEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserAccountEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

public class WSO2RegistrationEventPayloadBuilderTest {

    private static final int TENANT_ID = -1234;
    private static final String TENANT_DOMAIN = "example.com";
    private static final String TEST_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String TEST_USER_EMAIL = "tom@gmail.com";
    private static final String USER_NAME = "tom";
    private static final String DOMAIN_QUALIFIED_TEST_USER_NAME = "DEFAULT/tom";
    private static final Logger log = LoggerFactory.getLogger(WSO2RegistrationEventPayloadBuilderTest.class);
    @Mock
    private EventData mockEventData;

    @Mock
    private RealmService realmService;

    @Mock
    UserStoreManager userStoreManagerMock;

    @Mock
    private UserRealm userRealm;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private AbstractUserStoreManager userStoreManager;

    @InjectMocks
    private WSO2RegistrationEventPayloadBuilder payloadBuilder;

    @BeforeClass
    public void setup() throws Exception {

        MockitoAnnotations.openMocks(this);

        when(realmConfiguration.getUserStoreProperty(
                UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME)).thenReturn("DEFAULT");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);

        mockServiceURLBuilder();
        mockIdentityTenantUtil();
        CommonTestUtils.initPrivilegedCarbonContext();
    }

    @AfterClass
    public void teardown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        IdentityUtil.threadLocalProperties.remove();
    }

    @Test
    public void testTestGetEventSchemaType() {

        assertEquals(payloadBuilder.getEventSchemaType(), EventSchema.WSO2);
    }

    @Test
    public void testBuildRegistrationSuccessEvent() throws UserStoreException, IdentityEventException {

        Map<String, Object> params = new HashMap<>();
        params.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        params.put(USER_STORE_MANAGER, userStoreManager);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_TEST_USER_NAME);

        when(mockEventData.getEventParams()).thenReturn(params);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_TEST_USER_NAME),
                eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any())).thenReturn(TEST_USER_EMAIL);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_TEST_USER_NAME),
                eq(FrameworkConstants.USER_ID_CLAIM), any())).thenReturn(TEST_USER_ID);

        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.ACCOUNT_LOCK)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());

        EventPayload eventPayload = payloadBuilder.buildRegistrationSuccessEvent(mockEventData);
        assertCommonFields((WSO2BaseEventPayload) eventPayload);

        WSO2RegistrationSuccessEventPayload userAccountEventPayload =
                (WSO2RegistrationSuccessEventPayload) eventPayload;
        // Assert the user account event payload
        assertNotNull(userAccountEventPayload.getUser());
        assertEquals(userAccountEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(userAccountEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_ENDPOINT) + "/" + TEST_USER_ID);
        assertNotNull(userAccountEventPayload.getUser().getClaims());
        assertEquals(userAccountEventPayload.getUser().getClaims().size(), 3);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getValue(), TEST_USER_EMAIL);

        IdentityContext.destroyCurrentContext();
    }

    private static void assertCommonFields(WSO2BaseEventPayload wso2BaseEventPayload) {

        assertNotNull(wso2BaseEventPayload);

        assertNotNull(wso2BaseEventPayload.getInitiatorType());
        assertEquals(wso2BaseEventPayload.getInitiatorType(), Flow.InitiatingPersona.ADMIN.name());

        assertNotNull(wso2BaseEventPayload.getOrganization());
        assertEquals(wso2BaseEventPayload.getOrganization().getName(), TENANT_DOMAIN);

        assertNotNull(wso2BaseEventPayload.getUserStore());
        assertEquals(wso2BaseEventPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(wso2BaseEventPayload.getUserStore().getName(), "DEFAULT");
    }
}