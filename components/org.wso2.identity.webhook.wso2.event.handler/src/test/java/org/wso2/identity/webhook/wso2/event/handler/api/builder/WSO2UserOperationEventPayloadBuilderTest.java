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
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2BaseEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserAccountEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserGroupUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Group;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.PRE_DELETE_USER_ID;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

/**
 * Test class for WSO2UserOperationEventPayloadBuilder.
 */
public class WSO2UserOperationEventPayloadBuilderTest {

    private static final String ADDED_GROUP_ID = "36a4541a-1055-4986-872c-cdf2faa7a468";
    private static final String DELETED_GROUP_ID = "36a4541a-1055-4986-872c-cdf2faa7a468";
    private static final int TENANT_ID = -1234;
    private static final String TENANT_DOMAIN = "example.com";
    private static final String ROLE_NAME = "hr-group";
    private static final String GROUP_REF =
            "https://api.asg.io/t/myorg/scim2/Groups/96a4541a-1055-4986-872c-cdf2faa7a468";
    private static final String ADDED_USESR_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String DELETED_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String TEST_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String ADDED_USER_EMAIL = "john@gmail.com";
    private static final String DELETED_USER_EMAIL = "pearl@gmail.com";
    private static final String TEST_USER_EMAIL = "tom@gmail.com";
    private static final String DOMAIN_QUALIFIED_ADDED_USER_NAME = "DEFAULT/john";
    private static final String DOMAIN_QUALIFIED_DELETED_USER_NAME = "DEFAULT/pearl";
    private static final String DOMAIN_QUALIFIED_TEST_USER_NAME = "DEFAULT/tom";
    private static final String DEFAULT = "DEFAULT";

    @Mock
    private EventData mockEventData;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private AbstractUserStoreManager userStoreManager;

    @InjectMocks
    private WSO2UserOperationEventPayloadBuilder payloadBuilder;

    @BeforeClass
    public void setup() throws Exception {

        MockitoAnnotations.openMocks(this);

        when(realmConfiguration.getUserStoreProperty(
                UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME)).thenReturn(DEFAULT);
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

    @Test
    public void testBuildUserGroupUpdateEvent() throws IdentityEventException, UserStoreException {

        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.USER_GROUP_UPDATE)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());

        Map<String, Object> params = new HashMap<>();
        params.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        params.put(USER_STORE_MANAGER, userStoreManager);
        params.put(IdentityEventConstants.EventProperty.ROLE_NAME, ROLE_NAME);

        String[] addedUsers = new String[]{DOMAIN_QUALIFIED_ADDED_USER_NAME};
        params.put(IdentityEventConstants.EventProperty.NEW_USERS, addedUsers);
        String[] deletedUsers = new String[]{DOMAIN_QUALIFIED_DELETED_USER_NAME};
        params.put(IdentityEventConstants.EventProperty.DELETED_USERS, deletedUsers);

        when(mockEventData.getEventParams()).thenReturn(params);

        org.wso2.carbon.user.core.common.Group addedGroup = new org.wso2.carbon.user.core.common.Group();
        addedGroup.setGroupID(ADDED_GROUP_ID);
        addedGroup.setLocation(GROUP_REF);
        when(userStoreManager.getGroupByGroupName(ROLE_NAME, null)).thenReturn(addedGroup);

        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_ADDED_USER_NAME),
                eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any()))
                .thenReturn(ADDED_USER_EMAIL);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_ADDED_USER_NAME),
                eq(FrameworkConstants.USER_ID_CLAIM), any()))
                .thenReturn(ADDED_USESR_ID);

        org.wso2.carbon.user.core.common.Group removedGroup = new org.wso2.carbon.user.core.common.Group();
        removedGroup.setGroupID(DELETED_GROUP_ID);
        removedGroup.setLocation(GROUP_REF);
        when(userStoreManager.getGroupByGroupName(ROLE_NAME, null)).thenReturn(removedGroup);

        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_DELETED_USER_NAME),
                eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any()))
                .thenReturn(DELETED_USER_EMAIL);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_DELETED_USER_NAME),
                eq(FrameworkConstants.USER_ID_CLAIM), any()))
                .thenReturn(DELETED_USER_ID);

        EventPayload eventPayload = payloadBuilder.buildUserGroupUpdateEvent(mockEventData);
        assertCommonFields((WSO2BaseEventPayload) eventPayload);

        assertTrue(eventPayload instanceof WSO2UserGroupUpdateEventPayload);
        WSO2UserGroupUpdateEventPayload userGroupUpdateEventPayload = (WSO2UserGroupUpdateEventPayload) eventPayload;

        Group group = userGroupUpdateEventPayload.getGroup();
        assertNotNull(group);
        assertEquals(group.getId(), ADDED_GROUP_ID);
        assertEquals(group.getName(), ROLE_NAME);
        assertEquals(group.getRef(), GROUP_REF);

        assertNotNull(group.getAddedUsers());
        assertEquals(group.getAddedUsers().size(), 1);

        User addedUser = group.getAddedUsers().get(0);
        assertEquals(addedUser.getId(), ADDED_USESR_ID);
        assertNotNull(addedUser.getClaims());
        assertEquals(addedUser.getClaims().size(), 1);
        assertEquals(addedUser.getClaims().get(0).getUri(), FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(addedUser.getClaims().get(0).getValue(), ADDED_USER_EMAIL);

        assertNotNull(group.getRemovedUsers());
        assertEquals(group.getRemovedUsers().size(), 1);

        User removedUser = group.getRemovedUsers().get(0);
        assertEquals(removedUser.getId(), DELETED_USER_ID);
        assertNotNull(removedUser.getClaims());
        assertEquals(removedUser.getClaims().size(), 1);
        assertEquals(removedUser.getClaims().get(0).getUri(), FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(removedUser.getClaims().get(0).getValue(), DELETED_USER_EMAIL);

        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testBuildUserDeleteEvent() throws IdentityEventException, UserStoreException {

        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.USER_DELETE)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());

        Map<String, Object> params = new HashMap<>();
        params.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        params.put(USER_STORE_MANAGER, userStoreManager);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_DELETED_USER_NAME);

        when(mockEventData.getEventParams()).thenReturn(params);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_DELETED_USER_NAME),
                eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any()))
                .thenReturn(DELETED_USER_EMAIL);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_DELETED_USER_NAME),
                eq(FrameworkConstants.USER_ID_CLAIM), any()))
                .thenReturn(DELETED_USER_ID);

        EventPayload eventPayload = payloadBuilder.buildUserDeleteEvent(mockEventData);
        assertCommonFields((WSO2BaseEventPayload) eventPayload);

        WSO2UserAccountEventPayload userAccountEventPayload = (WSO2UserAccountEventPayload) eventPayload;

        // Assert the user account event payload
        assertNotNull(userAccountEventPayload.getUser());
        assertEquals(userAccountEventPayload.getUser().getId(), DELETED_USER_ID);
        assertEquals(userAccountEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + DELETED_USER_ID);
        assertNotNull(userAccountEventPayload.getUser().getClaims());
        assertEquals(userAccountEventPayload.getUser().getClaims().size(), 1);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.USERNAME_CLAIM);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getValue(),
                DOMAIN_QUALIFIED_DELETED_USER_NAME);

        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testBuildUserUnlockAccountEvent() throws IdentityEventException, UserStoreException {

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
                .name(Flow.Name.ACCOUNT_UNLOCK)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());

        EventPayload eventPayload = payloadBuilder.buildUserUnlockAccountEvent(mockEventData);
        WSO2BaseEventPayload wso2BaseEventPayload = (WSO2BaseEventPayload) eventPayload;
        assertNotNull(wso2BaseEventPayload.getTenant());
        assertEquals(wso2BaseEventPayload.getTenant().getName(), TENANT_DOMAIN);

        assertNotNull(wso2BaseEventPayload.getUserStore());
        assertEquals(wso2BaseEventPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(wso2BaseEventPayload.getUserStore().getName(), DEFAULT);

        WSO2UserAccountEventPayload userAccountEventPayload = (WSO2UserAccountEventPayload) eventPayload;
        // Assert the user account event payload
        assertNotNull(userAccountEventPayload.getUser());
        assertEquals(userAccountEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(userAccountEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);
        assertNotNull(userAccountEventPayload.getUser().getClaims());
        assertEquals(userAccountEventPayload.getUser().getClaims().size(), 1);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getValue(), TEST_USER_EMAIL);

        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testBuildUserLockAccountEvent() throws IdentityEventException, UserStoreException {

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

        EventPayload eventPayload = payloadBuilder.buildUserLockAccountEvent(mockEventData);
        WSO2BaseEventPayload wso2BaseEventPayload = (WSO2BaseEventPayload) eventPayload;
        assertNotNull(wso2BaseEventPayload.getTenant());
        assertEquals(wso2BaseEventPayload.getTenant().getName(), TENANT_DOMAIN);

        assertNotNull(wso2BaseEventPayload.getUserStore());
        assertEquals(wso2BaseEventPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(wso2BaseEventPayload.getUserStore().getName(), DEFAULT);

        WSO2UserAccountEventPayload userAccountEventPayload = (WSO2UserAccountEventPayload) eventPayload;
        // Assert the user account event payload
        assertNotNull(userAccountEventPayload.getUser());
        assertEquals(userAccountEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(userAccountEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);
        assertNotNull(userAccountEventPayload.getUser().getClaims());
        assertEquals(userAccountEventPayload.getUser().getClaims().size(), 1);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getValue(), TEST_USER_EMAIL);

        IdentityContext.destroyCurrentContext();
    }

    private static void assertCommonFields(WSO2BaseEventPayload wso2BaseEventPayload) {

        assertNotNull(wso2BaseEventPayload);

        assertNotNull(wso2BaseEventPayload.getInitiatorType());
        assertEquals(wso2BaseEventPayload.getInitiatorType(), Flow.InitiatingPersona.ADMIN.name());

        assertNotNull(wso2BaseEventPayload.getTenant());
        assertEquals(wso2BaseEventPayload.getTenant().getName(), TENANT_DOMAIN);

        assertNotNull(wso2BaseEventPayload.getUserStore());
        assertEquals(wso2BaseEventPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(wso2BaseEventPayload.getUserStore().getName(), DEFAULT);
    }

    @Test
    public void testBuildUserAccountEnableEvent() throws UserStoreException, IdentityEventException {

        Map<String, Object> params = new HashMap<>();
        params.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, DEFAULT);
        params.put(IdentityEventConstants.EventProperty.USER_ID, TEST_USER_ID);
        params.put(USER_STORE_MANAGER, userStoreManager);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_TEST_USER_NAME);

        when(mockEventData.getEventParams()).thenReturn(params);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_TEST_USER_NAME),
                eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any())).thenReturn(TEST_USER_EMAIL);

        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.ACCOUNT_DISABLE) //TODO change the flow when introduce ACCOUNT_ENABLE
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());

        EventPayload eventPayload = payloadBuilder.buildUserAccountEnableEvent(mockEventData);
        assertCommonFields((WSO2BaseEventPayload) eventPayload);

        WSO2UserAccountEventPayload userAccountEventPayload = (WSO2UserAccountEventPayload) eventPayload;
        // Assert the user account event payload
        assertNotNull(userAccountEventPayload.getUser());
        assertEquals(userAccountEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(userAccountEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);
        assertNotNull(userAccountEventPayload.getUser().getClaims());
        assertEquals(userAccountEventPayload.getUser().getClaims().size(), 1);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getValue(), TEST_USER_EMAIL);

        IdentityContext.destroyCurrentContext();
    }

    @Test
    public void testBuildUserAccountDisableEvent() throws IdentityEventException, UserStoreException {

        Map<String, Object> params = new HashMap<>();
        params.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        params.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);
        params.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, DEFAULT);
        params.put(IdentityEventConstants.EventProperty.USER_ID, TEST_USER_ID);
        params.put(USER_STORE_MANAGER, userStoreManager);
        params.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_TEST_USER_NAME);

        when(mockEventData.getEventParams()).thenReturn(params);
        when(userStoreManager.getUserClaimValue(eq(DOMAIN_QUALIFIED_TEST_USER_NAME),
                eq(FrameworkConstants.EMAIL_ADDRESS_CLAIM), any())).thenReturn(TEST_USER_EMAIL);

        IdentityContext.getThreadLocalIdentityContext().setFlow(new Flow.Builder()
                .name(Flow.Name.ACCOUNT_DISABLE)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build());

        EventPayload eventPayload = payloadBuilder.buildUserAccountEnableEvent(mockEventData);
        assertCommonFields((WSO2BaseEventPayload) eventPayload);

        WSO2UserAccountEventPayload userAccountEventPayload = (WSO2UserAccountEventPayload) eventPayload;
        // Assert the user account event payload
        assertNotNull(userAccountEventPayload.getUser());
        assertEquals(userAccountEventPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(userAccountEventPayload.getUser().getRef(),
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);
        assertNotNull(userAccountEventPayload.getUser().getClaims());
        assertEquals(userAccountEventPayload.getUser().getClaims().size(), 1);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getUri(),
                FrameworkConstants.EMAIL_ADDRESS_CLAIM);
        assertEquals(userAccountEventPayload.getUser().getClaims().get(0).getValue(), TEST_USER_EMAIL);

        IdentityContext.destroyCurrentContext();
    }
}
