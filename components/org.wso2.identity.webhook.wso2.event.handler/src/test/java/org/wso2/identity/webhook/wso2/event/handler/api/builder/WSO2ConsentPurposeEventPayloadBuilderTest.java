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
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.base.CarbonBaseConstants;
import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.consent.mgt.core.exception.ConsentManagementException;
import org.wso2.carbon.consent.mgt.core.model.Purpose;
import org.wso2.carbon.consent.mgt.core.model.PurposePIICategory;
import org.wso2.carbon.consent.mgt.core.model.PurposeVersion;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.Organization;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.core.context.util.IdentityContextUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2ConsentPurposeVersionAddedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import org.wso2.carbon.consent.mgt.core.constant.ConsentConstants;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockIdentityTenantUtil;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link WSO2ConsentPurposeEventPayloadBuilder}.
 */
public class WSO2ConsentPurposeEventPayloadBuilderTest {

    private static final String TENANT_DOMAIN = "carbon.super";
    private static final int TENANT_ID = 100;
    private static final String ORG_ID = "10084a8d-113f-4211-a0d5-efe36b082211";
    private static final String ORG_NAME = "myorg";
    private static final String ORG_HANDLE = "myorg";
    private static final String PURPOSE_ID = "f83aa1a3-5d4d-4c0e-84db-c3a4f1e6c8b2";
    private static final String PURPOSE_NAME = "Marketing Communications";
    private static final String PURPOSE_VERSION_STR = "v2";
    private static final String CLAIM_URI_1 = "http://wso2.org/claims/emailaddress";
    private static final String CLAIM_URI_2 = "http://wso2.org/claims/dob";
    private static final String SAMPLE_INITIATOR_IP = "192.168.1.10";

    @Mock
    private ConsentManager consentManager;

    private MockedStatic<IdentityContextUtil> identityContextUtil;
    private WSO2ConsentPurposeEventPayloadBuilder builder;

    @BeforeClass
    public void setUp() throws Exception {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "src", "test", "resources").toString();
        System.setProperty(CarbonBaseConstants.CARBON_HOME, carbonHome);

        MockitoAnnotations.openMocks(this);
        WSO2EventHookHandlerDataHolder.getInstance().setConsentManager(consentManager);

        mockServiceURLBuilder();
        mockIdentityTenantUtil();

        CommonTestUtils.initPrivilegedCarbonContext();

        identityContextUtil = mockStatic(IdentityContextUtil.class);
        identityContextUtil.when(IdentityContextUtil::getClientIpAddress).thenReturn(SAMPLE_INITIATOR_IP);

        RootOrganization rootOrganization = new RootOrganization.Builder()
                .associatedTenantId(TENANT_ID)
                .associatedTenantDomain(TENANT_DOMAIN)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setRootOrganization(rootOrganization);

        Organization organization = new Organization.Builder()
                .id(ORG_ID)
                .name(ORG_NAME)
                .organizationHandle(ORG_HANDLE)
                .depth(0)
                .build();
        IdentityContext.getThreadLocalIdentityContext().setOrganization(organization);

        Flow flow = new Flow.Builder()
                .name(Flow.Name.USER_ACCOUNT_DELETE)
                .initiatingPersona(Flow.InitiatingPersona.ADMIN)
                .build();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);

        builder = new WSO2ConsentPurposeEventPayloadBuilder();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        closeMockedIdentityTenantUtil();
        Mockito.reset(consentManager);
        if (identityContextUtil != null) {
            identityContextUtil.close();
        }
        IdentityContext.destroyCurrentContext();
        PrivilegedCarbonContext.endTenantFlow();
    }

    @Test
    public void testGetEventSchemaType() {

        assertEquals(builder.getEventSchemaType(), Constants.EventSchema.WSO2);
    }

    @Test
    public void testBuildPurposeVersionAddedEvent_elementsMapping()
            throws IdentityEventException, ConsentManagementException {

        Purpose purpose = mock(Purpose.class);
        when(purpose.getName()).thenReturn(PURPOSE_NAME);
        when(consentManager.getPurposeByUuid(PURPOSE_ID)).thenReturn(purpose);

        PurposePIICategory cat1 = mock(PurposePIICategory.class);
        when(cat1.getName()).thenReturn(CLAIM_URI_1);
        when(cat1.getMandatory()).thenReturn(Boolean.TRUE);

        PurposePIICategory cat2 = mock(PurposePIICategory.class);
        when(cat2.getName()).thenReturn(CLAIM_URI_2);
        when(cat2.getMandatory()).thenReturn(Boolean.FALSE);

        PurposeVersion purposeVersion = mock(PurposeVersion.class);
        when(purposeVersion.getVersion()).thenReturn(PURPOSE_VERSION_STR);
        when(purposeVersion.getPurposePIICategories()).thenReturn(Arrays.asList(cat1, cat2));

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.PURPOSE_ID, PURPOSE_ID);
        params.put(ConsentConstants.PURPOSE_VERSION, purposeVersion);
        params.put(ConsentConstants.SET_AS_LATEST, Boolean.TRUE);
        when(eventData.getEventParams()).thenReturn(params);

        EventPayload payload = builder.buildPurposeVersionAddedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2ConsentPurposeVersionAddedEventPayload);

        WSO2ConsentPurposeVersionAddedEventPayload typedPayload =
                (WSO2ConsentPurposeVersionAddedEventPayload) payload;

        assertEquals(typedPayload.getInitiatorType(), Flow.InitiatingPersona.ADMIN.name());
        assertEquals(typedPayload.getInitiatorIpAddress(), SAMPLE_INITIATOR_IP);

        assertNotNull(typedPayload.getTenant());
        assertEquals(typedPayload.getTenant().getName(), TENANT_DOMAIN);
        assertEquals(typedPayload.getTenant().getId(), String.valueOf(TENANT_ID));

        assertNotNull(typedPayload.getPurpose());
        assertEquals(typedPayload.getPurpose().getId(), PURPOSE_ID);
        assertEquals(typedPayload.getPurpose().getName(), PURPOSE_NAME);

        assertNotNull(typedPayload.getPurpose().getVersion());
        assertEquals(typedPayload.getPurpose().getVersion().getVersion(), PURPOSE_VERSION_STR);
        assertTrue(typedPayload.getPurpose().getVersion().isSetAsLatest());

        assertNotNull(typedPayload.getPurpose().getVersion().getElements());
        assertEquals(typedPayload.getPurpose().getVersion().getElements().size(), 2);
        assertEquals(typedPayload.getPurpose().getVersion().getElements().get(0).getName(), CLAIM_URI_1);
        assertTrue(typedPayload.getPurpose().getVersion().getElements().get(0).getMandatory());
        assertEquals(typedPayload.getPurpose().getVersion().getElements().get(1).getName(), CLAIM_URI_2);
        assertTrue(!typedPayload.getPurpose().getVersion().getElements().get(1).getMandatory());
    }

    @Test
    public void testBuildPurposeVersionAddedEvent_purposeNameResolutionFailure()
            throws IdentityEventException, ConsentManagementException {

        when(consentManager.getPurposeByUuid(PURPOSE_ID))
                .thenThrow(new ConsentManagementException("CONSENT-60002", "Purpose not found"));

        PurposePIICategory cat = mock(PurposePIICategory.class);
        when(cat.getName()).thenReturn(CLAIM_URI_1);
        when(cat.getMandatory()).thenReturn(Boolean.TRUE);

        PurposeVersion purposeVersion = mock(PurposeVersion.class);
        when(purposeVersion.getVersion()).thenReturn(PURPOSE_VERSION_STR);
        when(purposeVersion.getPurposePIICategories()).thenReturn(Arrays.asList(cat));

        EventData eventData = mock(EventData.class);
        Map<String, Object> params = new HashMap<>();
        params.put(ConsentConstants.PURPOSE_ID, PURPOSE_ID);
        params.put(ConsentConstants.PURPOSE_VERSION, purposeVersion);
        params.put(ConsentConstants.SET_AS_LATEST, Boolean.FALSE);
        when(eventData.getEventParams()).thenReturn(params);

        EventPayload payload = builder.buildPurposeVersionAddedEvent(eventData);

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2ConsentPurposeVersionAddedEventPayload);

        WSO2ConsentPurposeVersionAddedEventPayload typedPayload =
                (WSO2ConsentPurposeVersionAddedEventPayload) payload;

        assertNotNull(typedPayload.getPurpose());
        assertEquals(typedPayload.getPurpose().getId(), PURPOSE_ID);
        assertNull(typedPayload.getPurpose().getName());

        assertNotNull(typedPayload.getPurpose().getVersion());
        assertEquals(typedPayload.getPurpose().getVersion().getElements().size(), 1);
        assertEquals(typedPayload.getPurpose().getVersion().getElements().get(0).getName(), CLAIM_URI_1);
    }
}
