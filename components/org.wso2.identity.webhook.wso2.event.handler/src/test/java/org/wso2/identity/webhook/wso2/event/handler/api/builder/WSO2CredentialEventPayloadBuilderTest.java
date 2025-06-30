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
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
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
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.config.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2BaseEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserCredentialUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.testng.Assert.*;
import static org.wso2.carbon.identity.core.context.model.Flow.Name.GROUP_UPDATE;
import static org.wso2.carbon.identity.core.context.model.Flow.Name.PASSWORD_RESET;
import static org.wso2.carbon.identity.core.context.model.Flow.Name.PROFILE_UPDATE;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.PRE_DELETE_USER_ID;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

public class WSO2CredentialEventPayloadBuilderTest {

    private static final String TENANT_DOMAIN = "example.com";
    private static final String DELETED_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String TEST_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String TEST_USER_EMAIL = "tom@gmail.com";
    private static final String USER_NAME = "tom";
    private static final String DOMAIN_QUALIFIED_TEST_USER_NAME = "DEFAULT/tom";
    private static final Logger log = LoggerFactory.getLogger(WSO2CredentialEventPayloadBuilderTest.class);
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
    private WSO2CredentialEventPayloadBuilder payloadBuilder;

    @BeforeClass
    public void setup() throws Exception {

        MockitoAnnotations.openMocks(this);

        when(realmConfiguration.getUserStoreProperty(
                UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME)).thenReturn("DEFAULT");
        when(userStoreManager.getRealmConfiguration()).thenReturn(realmConfiguration);

        mockServiceURLBuilder();
        mockIdentityTenantUtil();

        Map<String, Object> threadLocalMap = new HashMap<>();
        threadLocalMap.put(PRE_DELETE_USER_ID, DELETED_USER_ID);
        IdentityUtil.threadLocalProperties.set(threadLocalMap);
        CommonTestUtils.initPrivilegedCarbonContext();
    }

    @AfterClass
    public void teardown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        IdentityUtil.threadLocalProperties.remove();
    }

    @Test
    public void testGetEventSchemaType() {

        assertEquals(payloadBuilder.getEventSchemaType(), EventSchema.WSO2);
    }

    @DataProvider(name = "actionDataProvider")
    public Object[][] actionDataProvider() {

        return new Object[][]{
                {PROFILE_UPDATE},
                {PASSWORD_RESET},
                {GROUP_UPDATE},
                {null}
        };
    }

    @Test(dataProvider = "actionDataProvider")
    public void testBuildCredentialUpdateEvent(Flow.Name flowName) throws IdentityEventException {

        Map<String, Object> params = new HashMap<>();
        params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, "DEFAULT");
        params.put(IdentityEventConstants.EventProperty.USER_NAME, USER_NAME);

        when(mockEventData.getEventParams()).thenReturn(params);
        mockUserStoreManager();
        try {
            when(userStoreManagerMock.getUserClaimValue(eq(DOMAIN_QUALIFIED_TEST_USER_NAME),
                    eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any())).thenReturn(TEST_USER_EMAIL);
            when(userStoreManagerMock.getUserClaimValue(eq(DOMAIN_QUALIFIED_TEST_USER_NAME),
                    eq(FrameworkConstants.USER_ID_CLAIM), any())).thenReturn(TEST_USER_ID);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error while getting user claim value.", e);
        }

        if (flowName != null) {
            IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                    .name(flowName)
                    .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                    .build());
        }

        EventPayload eventPayload = payloadBuilder.buildCredentialUpdateEvent(mockEventData);

        assertCommonFields((WSO2BaseEventPayload) eventPayload);

        WSO2UserCredentialUpdateEventPayload userCredentialUpdateEventPayload =
                (WSO2UserCredentialUpdateEventPayload) eventPayload;

        assertNotNull(userCredentialUpdateEventPayload.getUser());
        assertEquals(userCredentialUpdateEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(userCredentialUpdateEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + DELETED_USER_ID);
        assertNotNull(userCredentialUpdateEventPayload.getUser().getClaims());
        assertEquals(userCredentialUpdateEventPayload.getUser().getClaims().size(), 1);
        assertEquals(userCredentialUpdateEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(userCredentialUpdateEventPayload.getUser().getClaims().get(0).getValue(), TEST_USER_EMAIL);

        assertNotNull(userCredentialUpdateEventPayload.getCredentialType());
        assertEquals(userCredentialUpdateEventPayload.getCredentialType(), "PASSWORD");

        if (flowName == null) {
            assertNull(userCredentialUpdateEventPayload.getAction());
            assertNull(userCredentialUpdateEventPayload.getInitiatorType());
        } else if (flowName.equals(PROFILE_UPDATE)) {
            assertNotNull(userCredentialUpdateEventPayload.getAction());
            assertEquals(userCredentialUpdateEventPayload.getAction(),
                    WSO2CredentialEventPayloadBuilder.PasswordUpdateAction.UPDATE.name());
            assertEquals(userCredentialUpdateEventPayload.getInitiatorType(), Flow.InitiatingPersona.ADMIN.name());
        } else if (flowName.equals(PASSWORD_RESET)) {
            assertNotNull(userCredentialUpdateEventPayload.getAction());
            assertEquals(userCredentialUpdateEventPayload.getAction(),
                    WSO2CredentialEventPayloadBuilder.PasswordUpdateAction.RESET.name());
            assertEquals(userCredentialUpdateEventPayload.getInitiatorType(), Flow.InitiatingPersona.ADMIN.name());
        }

        IdentityContext.destroyCurrentContext();
    }

    private void mockUserStoreManager() {

        try {
            when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
            when(userRealm.getUserStoreManager()).thenReturn(userStoreManagerMock);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            log.error("Error while getting user store manager.", e);
        }

        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);
    }

    private static void assertCommonFields(WSO2BaseEventPayload wso2BaseEventPayload) {

        assertNotNull(wso2BaseEventPayload);

        assertNotNull(wso2BaseEventPayload.getTenant());
        assertEquals(wso2BaseEventPayload.getTenant().getName(), TENANT_DOMAIN);

        assertNotNull(wso2BaseEventPayload.getUserStore());
        assertEquals(wso2BaseEventPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(wso2BaseEventPayload.getUserStore().getName(), "DEFAULT");
    }
}
