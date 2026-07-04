/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.role.v2.mgt.core.RoleManagementService;
import org.wso2.carbon.identity.role.v2.mgt.core.model.IdpGroup;
import org.wso2.carbon.identity.role.v2.mgt.core.model.Permission;
import org.wso2.carbon.identity.role.v2.mgt.core.model.RoleBasicInfo;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.Group;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleDeletedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleGroupsUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleIdpGroupsUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RolePermissionsUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleMetaUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.GroupEntry;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.UserEntry;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RoleUsersUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link WSO2RoleManagementEventPayloadBuilder}.
 */
public class WSO2RoleManagementEventPayloadBuilderTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = -1234;
    private static final String ROLE_ID = "test-role-id-001";
    private static final String ROLE_NAME = "TestRole";
    private static final String AUDIENCE_TYPE = "application";
    private static final String AUDIENCE_ID = "app-001";
    private static final String AUDIENCE_NAME = "TestApp";
    private static final String USER_ID_1 = "user-001";
    private static final String USER_ID_2 = "user-002";
    private static final String USERNAME_1 = "alice";
    private static final String USERNAME_2 = "agent-01";
    private static final String AGENT_NAME_2 = "Support Agent";
    private static final String USER_STORE_1 = "PRIMARY";
    private static final String USER_STORE_2 = "AGENT";
    private static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";
    private static final String AGENT_NAME_CLAIM_URI = "http://wso2.org/claims/agent/Name";
    private static final String GROUP_ID_1 = "group-001";
    private static final String GROUP_NAME_1 = "dev-team";
    private static final String GROUP_USER_STORE = "PRIMARY";
    private static final String IDP_ID_1 = "idp-resource-001";
    private static final String IDP_NAME_1 = "SampleIdP";

    @Mock
    private RoleManagementService roleManagementService;
    @Mock
    private RealmService realmService;
    @Mock
    private AbstractUserStoreManager userStoreManager;
    @Mock
    private IdpManager idpManager;

    private MockedStatic<IdentityTenantUtil> mockedIdentityTenantUtil;
    private WSO2RoleManagementEventPayloadBuilder builder;

    @BeforeClass
    void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);

        RoleBasicInfo roleBasicInfo = new RoleBasicInfo(ROLE_ID, ROLE_NAME);
        roleBasicInfo.setAudience(AUDIENCE_TYPE);
        roleBasicInfo.setAudienceId(AUDIENCE_ID);
        roleBasicInfo.setAudienceName(AUDIENCE_NAME);
        when(roleManagementService.getRoleBasicInfoById(anyString(), anyString())).thenReturn(roleBasicInfo);
        WSO2EventHookHandlerDataHolder.getInstance().setRoleManagementService(roleManagementService);

        // Wire RealmService → UserStoreManager for username/groupName enrichment.
        UserRealm userRealm = mock(UserRealm.class);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManager);
        when(realmService.getTenantUserRealm(TENANT_ID)).thenReturn(userRealm);
        // USER_ID_1 → normal PRIMARY user (username claim only).
        // USER_ID_2 → AGENT user-store user (username + agent Name claim).
        when(userStoreManager.getUserNameFromUserID(USER_ID_1)).thenReturn(USERNAME_1);
        when(userStoreManager.getUserNameFromUserID(USER_ID_2)).thenReturn(USER_STORE_2 + "/" + USERNAME_2);
        Map<String, String> user1Claims = new HashMap<>();
        user1Claims.put(USERNAME_CLAIM_URI, USERNAME_1);
        when(userStoreManager.getUserClaimValuesWithID(
                USER_ID_1, new String[]{USERNAME_CLAIM_URI, AGENT_NAME_CLAIM_URI}, null))
                .thenReturn(user1Claims);
        Map<String, String> user2Claims = new HashMap<>();
        user2Claims.put(USERNAME_CLAIM_URI, USERNAME_2);
        user2Claims.put(AGENT_NAME_CLAIM_URI, AGENT_NAME_2);
        when(userStoreManager.getUserClaimValuesWithID(
                USER_ID_2, new String[]{USERNAME_CLAIM_URI, AGENT_NAME_CLAIM_URI}, null))
                .thenReturn(user2Claims);
        Group group1 = mock(Group.class);
        when(group1.getGroupName()).thenReturn(GROUP_NAME_1);
        when(group1.getUserStoreDomain()).thenReturn(GROUP_USER_STORE);
        when(userStoreManager.getGroup(GROUP_ID_1, null)).thenReturn(group1);
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);

        // Wire IdpManager for idpName enrichment.
        IdentityProvider idp = mock(IdentityProvider.class);
        when(idp.getIdentityProviderName()).thenReturn(IDP_NAME_1);
        when(idpManager.getIdPByResourceId(IDP_ID_1, TENANT_DOMAIN, true)).thenReturn(idp);
        WSO2EventHookHandlerDataHolder.getInstance().setIdpManager(idpManager);

        mockServiceURLBuilder();

        // IdentityTenantUtil mock for TENANT_DOMAIN used in getAbstractUserStoreManager.
        mockedIdentityTenantUtil = mockStatic(IdentityTenantUtil.class);
        mockedIdentityTenantUtil.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN)).thenReturn(TENANT_ID);

        CommonTestUtils.initPrivilegedCarbonContext();

        Flow flow = new Flow.Builder()
                .name(Flow.Name.USER_GROUP_UPDATE)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);

        if (IdentityContext.getThreadLocalIdentityContext().getRootOrganization() == null) {
            RootOrganization rootOrganization = new RootOrganization.Builder()
                    .associatedTenantDomain(TENANT_DOMAIN)
                    .associatedTenantId(TENANT_ID)
                    .build();
            IdentityContext.getThreadLocalIdentityContext().setRootOrganization(rootOrganization);
        }

        if (IdentityContext.getThreadLocalIdentityContext().getOrganization() == null) {
            Organization organization = new Organization.Builder()
                    .id("org-001")
                    .name("Test Organization")
                    .organizationHandle(TENANT_DOMAIN)
                    .depth(0)
                    .build();
            IdentityContext.getThreadLocalIdentityContext().setOrganization(organization);
        }

        builder = new WSO2RoleManagementEventPayloadBuilder();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        if (mockedIdentityTenantUtil != null) {
            mockedIdentityTenantUtil.close();
        }
        IdentityContext.getThreadLocalIdentityContext().exitFlow();
    }

    @Test
    public void testGetEventSchemaType() {

        assertEquals(builder.getEventSchemaType(), Constants.EventSchema.WSO2);
    }

    @Test
    public void testBuildRoleCreatedEventReturnsCorrectType() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(buildRoleCreatedProperties());
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleCreatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleCreatedEventPayload);

        WSO2RoleCreatedEventPayload created = (WSO2RoleCreatedEventPayload) payload;
        assertNotNull(created.getRole());
        assertEquals(created.getRole().getId(), ROLE_ID);
    }

    @Test
    public void testBuildRoleCreatedEventWithUsersAndGroups() throws IdentityEventException {

        Map<String, Object> props = buildRoleCreatedProperties();
        props.put(IdentityEventConstants.EventProperty.USER_LIST, Arrays.asList(USER_ID_1, USER_ID_2));
        props.put(IdentityEventConstants.EventProperty.GROUP_LIST, Arrays.asList(GROUP_ID_1));

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleCreatedEvent(eventData);

        WSO2RoleCreatedEventPayload created = (WSO2RoleCreatedEventPayload) payload;
        assertNotNull(created.getRole().getUsers());
        assertEquals(created.getRole().getUsers().size(), 2);
        UserEntry user1 = created.getRole().getUsers().get(0);
        assertEquals(user1.getId(), USER_ID_1);
        assertEquals(user1.getUserStoreDomain(), USER_STORE_1);
        assertNotNull(user1.getRef());
        assertUsernameClaim(user1, USERNAME_1);
        assertNoAgentNameClaim(user1);
        UserEntry user2 = created.getRole().getUsers().get(1);
        assertEquals(user2.getId(), USER_ID_2);
        assertEquals(user2.getUserStoreDomain(), USER_STORE_2);
        assertNotNull(user2.getRef());
        assertUsernameClaim(user2, USERNAME_2);
        assertAgentNameClaim(user2, AGENT_NAME_2);
        assertNotNull(created.getRole().getGroups());
        assertEquals(created.getRole().getGroups().size(), 1);
        GroupEntry group1 = created.getRole().getGroups().get(0);
        assertEquals(group1.getId(), GROUP_ID_1);
        assertEquals(group1.getGroupName(), GROUP_NAME_1);
        assertEquals(group1.getUserStoreDomain(), GROUP_USER_STORE);
    }

    @Test
    public void testBuildRoleCreatedEventWithPermissions() throws IdentityEventException {

        Permission perm = new Permission("read", "Read permission");
        Map<String, Object> props = buildRoleCreatedProperties();
        props.put(IdentityEventConstants.EventProperty.PERMISSIONS, Collections.singletonList(perm));

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleCreatedEvent(eventData);

        WSO2RoleCreatedEventPayload created = (WSO2RoleCreatedEventPayload) payload;
        assertNotNull(created.getRole().getPermissions());
        assertEquals(created.getRole().getPermissions().size(), 1);
        assertEquals(created.getRole().getPermissions().get(0), "read");
    }

    @Test
    public void testBuildRoleMetaUpdatedEventReturnsCorrectType() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.NEW_ROLE_NAME, "UpdatedRoleName");
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleMetaUpdatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleMetaUpdatedEventPayload);

        WSO2RoleMetaUpdatedEventPayload updated = (WSO2RoleMetaUpdatedEventPayload) payload;
        assertNotNull(updated.getRole());
        assertEquals(updated.getRole().getId(), ROLE_ID);
        assertEquals(updated.getRole().getName(), "UpdatedRoleName");
    }

    @Test
    public void testBuildRoleDeletedEventReturnsCorrectType() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleDeletedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleDeletedEventPayload);

        WSO2RoleDeletedEventPayload deleted = (WSO2RoleDeletedEventPayload) payload;
        assertNotNull(deleted.getRole());
        assertEquals(deleted.getRole().getId(), ROLE_ID);
    }

    @Test
    public void testBuildRoleUsersUpdatedEventReturnsCorrectType() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.NEW_USER_ID_LIST, Arrays.asList(USER_ID_1));
        props.put(IdentityEventConstants.EventProperty.DELETE_USER_ID_LIST, Arrays.asList(USER_ID_2));
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleUsersUpdatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleUsersUpdatedEventPayload);

        WSO2RoleUsersUpdatedEventPayload userList = (WSO2RoleUsersUpdatedEventPayload) payload;
        assertNotNull(userList.getRole());
        assertNotNull(userList.getRole().getAddedUsers());
        assertEquals(userList.getRole().getAddedUsers().size(), 1);
        UserEntry addedUser = userList.getRole().getAddedUsers().get(0);
        assertEquals(addedUser.getId(), USER_ID_1);
        assertEquals(addedUser.getUserStoreDomain(), USER_STORE_1);
        assertNotNull(addedUser.getRef());
        assertUsernameClaim(addedUser, USERNAME_1);
        assertNoAgentNameClaim(addedUser);
        assertNotNull(userList.getRole().getRemovedUsers());
        assertEquals(userList.getRole().getRemovedUsers().size(), 1);
        UserEntry removedUser = userList.getRole().getRemovedUsers().get(0);
        assertEquals(removedUser.getId(), USER_ID_2);
        assertEquals(removedUser.getUserStoreDomain(), USER_STORE_2);
        assertNotNull(removedUser.getRef());
        assertUsernameClaim(removedUser, USERNAME_2);
        assertAgentNameClaim(removedUser, AGENT_NAME_2);
    }

    @Test
    public void testBuildRoleGroupsUpdatedEventReturnsCorrectType() throws IdentityEventException {

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.NEW_GROUP_ID_LIST, Arrays.asList(GROUP_ID_1));
        props.put(IdentityEventConstants.EventProperty.DELETE_GROUP_ID_LIST, Collections.emptyList());
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleGroupsUpdatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleGroupsUpdatedEventPayload);

        WSO2RoleGroupsUpdatedEventPayload groupList = (WSO2RoleGroupsUpdatedEventPayload) payload;
        assertNotNull(groupList.getRole());
        assertNotNull(groupList.getRole().getAddedGroups());
        assertEquals(groupList.getRole().getAddedGroups().size(), 1);
        GroupEntry addedGroup = groupList.getRole().getAddedGroups().get(0);
        assertEquals(addedGroup.getId(), GROUP_ID_1);
        assertEquals(addedGroup.getGroupName(), GROUP_NAME_1);
        assertEquals(addedGroup.getUserStoreDomain(), GROUP_USER_STORE);
    }

    @Test
    public void testBuildRoleIdpGroupsUpdatedEventResolvesIdpName() throws IdentityEventException {

        IdpGroup idpGroup = new IdpGroup("idp-group-001", IDP_ID_1);
        idpGroup.setGroupName("IdpGroupOne");

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.NEW_GROUP_ID_LIST,
                Collections.singletonList(idpGroup));
        props.put(IdentityEventConstants.EventProperty.DELETE_GROUP_ID_LIST, Collections.emptyList());
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleIdpGroupsUpdatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleIdpGroupsUpdatedEventPayload);

        WSO2RoleIdpGroupsUpdatedEventPayload idpGroupList = (WSO2RoleIdpGroupsUpdatedEventPayload) payload;
        assertNotNull(idpGroupList.getRole());
        assertNotNull(idpGroupList.getRole().getAddedIdpGroups());
        assertEquals(idpGroupList.getRole().getAddedIdpGroups().size(), 1);

        WSO2RoleIdpGroupsUpdatedEventPayload.IdpGroupEntry entry =
                idpGroupList.getRole().getAddedIdpGroups().get(0);
        assertEquals(entry.getGroupId(), "idp-group-001");
        assertEquals(entry.getIdpId(), IDP_ID_1);
        assertEquals(entry.getIdpName(), IDP_NAME_1);
    }

    @Test
    public void testBuildRoleIdpGroupsUpdatedEventPreservesExistingIdpName() throws IdentityEventException {

        IdpGroup idpGroup = new IdpGroup("idp-group-002", "idp-resource-002");
        idpGroup.setGroupName("IdpGroupTwo");
        idpGroup.setIdpName("ExistingIdP");

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.NEW_GROUP_ID_LIST,
                Collections.singletonList(idpGroup));
        props.put(IdentityEventConstants.EventProperty.DELETE_GROUP_ID_LIST, Collections.emptyList());
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleIdpGroupsUpdatedEvent(eventData);

        WSO2RoleIdpGroupsUpdatedEventPayload idpGroupList = (WSO2RoleIdpGroupsUpdatedEventPayload) payload;
        assertEquals(idpGroupList.getRole().getAddedIdpGroups().get(0).getIdpName(), "ExistingIdP");
    }

    @Test
    public void testBuildRolePermissionsUpdatedEventReturnsCorrectType() throws IdentityEventException {

        Permission perm = new Permission("write", "Write permission");

        EventData eventData = mock(EventData.class);
        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.ADDED_PERMISSIONS,
                Collections.singletonList(perm));
        props.put(IdentityEventConstants.EventProperty.DELETED_PERMISSIONS, Collections.emptyList());
        when(eventData.getEventParams()).thenReturn(props);
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRolePermissionsUpdatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RolePermissionsUpdatedEventPayload);

        WSO2RolePermissionsUpdatedEventPayload permsPayload = (WSO2RolePermissionsUpdatedEventPayload) payload;
        assertNotNull(permsPayload.getRole());
        assertNotNull(permsPayload.getRole().getAddedPermissions());
        assertEquals(permsPayload.getRole().getAddedPermissions().size(), 1);
        assertEquals(permsPayload.getRole().getAddedPermissions().get(0), "write");
    }

    @Test
    public void testBuildRoleCreatedEventWithNoEnrichmentWhenServiceUnavailable() throws IdentityEventException {

        WSO2EventHookHandlerDataHolder.getInstance().setRoleManagementService(null);

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(buildRoleCreatedProperties());
        when(eventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        EventPayload payload = builder.buildRoleCreatedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2RoleCreatedEventPayload);

        // Restore
        WSO2EventHookHandlerDataHolder.getInstance().setRoleManagementService(roleManagementService);
    }

    // ---- helpers ----

    private Map<String, Object> buildRoleCreatedProperties() {

        Map<String, Object> props = new HashMap<>();
        props.put(IdentityEventConstants.EventProperty.ROLE_ID, ROLE_ID);
        props.put(IdentityEventConstants.EventProperty.AUDIENCE, AUDIENCE_TYPE);
        props.put(IdentityEventConstants.EventProperty.AUDIENCE_ID, AUDIENCE_ID);
        return props;
    }

    private void assertUsernameClaim(UserEntry entry, String expectedUsername) {

        assertNotNull(entry.getClaims());
        Object value = entry.getClaims().stream()
                .filter(c -> USERNAME_CLAIM_URI.equals(c.getUri()))
                .map(c -> c.getValue())
                .findFirst()
                .orElse(null);
        assertEquals(value, expectedUsername);
    }

    private void assertAgentNameClaim(UserEntry entry, String expectedAgentName) {

        assertNotNull(entry.getClaims());
        Object value = entry.getClaims().stream()
                .filter(c -> AGENT_NAME_CLAIM_URI.equals(c.getUri()))
                .map(c -> c.getValue())
                .findFirst()
                .orElse(null);
        assertEquals(value, expectedAgentName);
    }

    private void assertNoAgentNameClaim(UserEntry entry) {

        if (entry.getClaims() == null) {
            return;
        }
        boolean hasAgentName = entry.getClaims().stream()
                .anyMatch(c -> AGENT_NAME_CLAIM_URI.equals(c.getUri()));
        assertEquals(hasAgentName, false);
    }
}
