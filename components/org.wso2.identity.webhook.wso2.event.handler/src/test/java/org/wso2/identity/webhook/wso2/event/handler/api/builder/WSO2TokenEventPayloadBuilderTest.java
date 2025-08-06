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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.config.RealmConfiguration;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenIssuedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils.constructFullURLWithEndpoint;

public class WSO2TokenEventPayloadBuilderTest {

    private static final int TENANT_ID = -1234;
    private static final String TENANT_DOMAIN = "example.com";
    private static final String TEST_USER_ID = "22e46698-7fa7-4497-90fc-e12864e30b77";
    private static final String DOMAIN_QUALIFIED_TEST_USER_NAME = "DEFAULT/tom";
    public static final String DEFAULT_USER_STORE = "DEFAULT";

    private WSO2TokenEventPayloadBuilder builder;

    @Mock
    private RealmConfiguration realmConfiguration;

    @Mock
    private RealmService realmService;

    @Mock
    UserStoreManager userStoreManagerMock;

    @Mock
    private UserRealm userRealm;

    @Mock
    private AbstractUserStoreManager userStoreManager;

    @Mock
    private ClaimMetadataManagementService claimMetadataManagementService;

    private MockedStatic<FrameworkUtils> frameworkUtils;

    @BeforeClass
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setClaimMetadataManagementService(claimMetadataManagementService);
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);

        when(realmService.getTenantUserRealm(anyInt())).thenReturn(userRealm);
        when(userRealm.getUserStoreManager()).thenReturn(userStoreManagerMock);

        mockServiceURLBuilder();
        mockIdentityTenantUtil();

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");

        CommonTestUtils.initPrivilegedCarbonContext();
        builder = new WSO2TokenEventPayloadBuilder();
    }

    @Test
    void testGetEventSchemaType() {

        assertEquals(builder.getEventSchemaType(), Constants.EventSchema.WSO2);
    }

    @Test
    void testBuildAccessTokenRevokeEventReturnsNonNullPayload() throws IdentityEventException {

        EventData mockEventData = mock(EventData.class);
        EventPayload payload = builder.buildAccessTokenRevokeEvent(mockEventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2TokenRevokedEventPayload);
    }

    @Test
    void testBuildAccessTokenIssueEventWithValidPropertiesAndFlow() throws IdentityEventException {

        EventData mockEventData = mock(EventData.class);

        Map<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.IAT, "12345");
        properties.put(IdentityEventConstants.EventProperty.TOKEN_TYPE, "Opaque");
        properties.put(IdentityEventConstants.EventProperty.GRANT_TYPE, "password");
        properties.put(IdentityEventConstants.EventProperty.JTI, "jti-001");
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_ID, "app-123");
        properties.put(IdentityEventConstants.EventProperty.APPLICATION_NAME, "SampleApp");
        properties.put(IdentityEventConstants.EventProperty.CONSUMER_KEY, "consumer-xyz");
        properties.put(IdentityEventConstants.EventProperty.TENANT_ID, TENANT_ID);
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, TENANT_DOMAIN);

        properties.put(IdentityEventConstants.EventProperty.USER_ID, TEST_USER_ID);
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, DOMAIN_QUALIFIED_TEST_USER_NAME);
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, DEFAULT_USER_STORE);

        when(mockEventData.getProperties()).thenReturn(properties);
        when(mockEventData.getTenantDomain()).thenReturn(TENANT_DOMAIN);

        Flow flow = new Flow.Builder().name(Flow.Name.LOGIN).initiatingPersona(Flow.InitiatingPersona.USER).build();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);

        RootOrganization rootOrganization = new RootOrganization.Builder()
                .associatedTenantId(100)
                .associatedTenantDomain(TENANT_DOMAIN)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setRootOrganization(rootOrganization);

        Organization organization = new Organization.Builder()
                .id("org-123")
                .name("Sample Organization")
                .organizationHandle(TENANT_DOMAIN)
                .depth(1)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setOrganization(organization);

        EventPayload payload = builder.buildAccessTokenIssueEvent(mockEventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2TokenIssuedEventPayload);

        WSO2TokenIssuedEventPayload issuedPayload = (WSO2TokenIssuedEventPayload) payload;
        assertNotNull(issuedPayload.getAccessToken());
        assertEquals(issuedPayload.getAccessToken().getTokenType(), "Opaque");
        assertEquals(issuedPayload.getApplication().getId(), "app-123");
        assertEquals(issuedPayload.getInitiatorType(), Flow.InitiatingPersona.USER.name());
        assertEquals(issuedPayload.getAction(), Flow.Name.LOGIN.name());

        assertNotNull(issuedPayload.getUser());
        assertEquals(issuedPayload.getUser().getId(), TEST_USER_ID);
        assertEquals(issuedPayload.getUser().getRef(),
                constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + TEST_USER_ID);

        assertNotNull(issuedPayload.getUserStore());
        assertEquals(issuedPayload.getUserStore().getId(), "REVGQVVMVA==");
        assertEquals(issuedPayload.getUserStore().getName(), DEFAULT_USER_STORE);

        IdentityContext.getThreadLocalIdentityContext().exitFlow();
    }

    @AfterClass
    public void teardown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        Mockito.reset(realmConfiguration, claimMetadataManagementService, userStoreManager, realmService);
        PrivilegedCarbonContext.endTenantFlow();
        frameworkUtils.close();
    }

}
