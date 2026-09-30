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
import org.mockito.MockitoAnnotations;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.context.model.RootOrganization;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.identity.organization.management.service.model.OrganizationAttribute;
import org.wso2.carbon.identity.organization.management.service.model.PatchOperation;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationDeletedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.TargetOrganization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UpdatedValues;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.CommonTestUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_DEPTH_IN_HIERARCHY;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_PATCH_OPERATIONS;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_PREVIOUS_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_OP_ADD;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_OP_REMOVE;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_OP_REPLACE;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_ATTRIBUTES;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_DESCRIPTION;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_NAME;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.PATCH_PATH_ORG_STATUS;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.closeMockedServiceURLBuilder;
import static org.wso2.identity.webhook.wso2.event.handler.internal.util.TestUtils.mockServiceURLBuilder;

/**
 * Unit tests for {@link WSO2OrganizationManagementEventPayloadBuilder}.
 */
public class WSO2OrganizationManagementEventPayloadBuilderTest {

    private static final String ORG_ID = "b537b54f-ec3d-452b-a20d-fc99f90a351a";
    private static final String ORG_NAME = "ABC Builders";
    private static final String ORG_HANDLE = "abcbuilders";
    private static final int ORG_DEPTH = 1;
    private static final int PUBLISHED_DELETE_DEPTH = 2;
    private static final String RESOLVED_ORG_NAME = "ABC Builders resolved";
    private static final String RESOLVED_ORG_HANDLE = "abcbuilders-resolved";
    private static final String ORGANIZATIONS_REF_PREFIX =
            "https://localhost:9443/t/myorg/api/server/v1/organizations/";

    private static final String ATTRIBUTE_COUNTRY = "Country";
    private static final String ATTRIBUTE_INDUSTRY = "Industry";
    private static final String ATTRIBUTE_REGION = "Region";
    private static final String COUNTRY_USA = "USA";
    private static final String COUNTRY_UK = "UK";
    private static final String INDUSTRY_CONSTRUCTION = "Construction";
    private static final String REGION_EMEA = "EMEA";

    private static final String UPDATED_NAME = "ABC Builders updated";
    private static final String UPDATED_DESCRIPTION = "ABC Builders description";
    private static final String PREVIOUS_DESCRIPTION = "Building constructions";
    private static final String STATUS_ACTIVE = "ACTIVE";
    private static final String STATUS_DISABLED = "DISABLED";

    /*
     The organization flow names are introduced by the framework change that accompanies this feature, and the
     released framework version this module builds against does not carry them yet. Since the builder only reads
     whichever flow is current, an existing flow name stands in and the expected action is derived from it.
    */
    private static final Flow.Name TEST_FLOW_NAME = Flow.Name.USER_GROUP_UPDATE;
    private static final Flow.InitiatingPersona TEST_INITIATING_PERSONA = Flow.InitiatingPersona.ADMIN;

    @Mock
    private OrganizationManager organizationManager;

    private WSO2OrganizationManagementEventPayloadBuilder builder;
    private String expectedTenantId;
    private String expectedTenantDomain;
    private String expectedContextOrganizationId;

    @BeforeClass
    public void setUp() throws Exception {

        MockitoAnnotations.openMocks(this);

        when(organizationManager.getOrganizationDepthInHierarchy(ORG_ID)).thenReturn(ORG_DEPTH);
        when(organizationManager.getOrganizationNameById(ORG_ID)).thenReturn(RESOLVED_ORG_NAME);
        when(organizationManager.resolveTenantDomain(ORG_ID)).thenReturn(RESOLVED_ORG_HANDLE);
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);

        mockServiceURLBuilder();
        CommonTestUtils.initPrivilegedCarbonContext();

        Flow flow = new Flow.Builder()
                .name(TEST_FLOW_NAME)
                .initiatingPersona(TEST_INITIATING_PERSONA)
                .build();
        IdentityContext.getThreadLocalIdentityContext().enterFlow(flow);

        if (IdentityContext.getThreadLocalIdentityContext().getRootOrganization() == null) {
            RootOrganization rootOrganization = new RootOrganization.Builder()
                    .associatedTenantDomain("carbon.super")
                    .associatedTenantId(-1234)
                    .build();
            IdentityContext.getThreadLocalIdentityContext().setRootOrganization(rootOrganization);
        }
        if (IdentityContext.getThreadLocalIdentityContext().getOrganization() == null) {
            org.wso2.carbon.identity.core.context.model.Organization contextOrganization =
                    new org.wso2.carbon.identity.core.context.model.Organization.Builder()
                            .id("10084a8d-113f-4211-a0d5-efe36b082211")
                            .name("Super")
                            .organizationHandle("carbon.super")
                            .depth(0)
                            .build();
            IdentityContext.getThreadLocalIdentityContext().setOrganization(contextOrganization);
        }

        /*
         The identity context is thread local and shared with the other builder tests, so the envelope
         expectations are taken from whatever the context ended up holding rather than from local constants.
        */
        expectedTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        expectedTenantDomain =
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain();
        expectedContextOrganizationId = IdentityContext.getThreadLocalIdentityContext().getOrganization().getId();

        builder = new WSO2OrganizationManagementEventPayloadBuilder();
    }

    @AfterClass
    public void tearDown() {

        closeMockedServiceURLBuilder();
        IdentityContext.getThreadLocalIdentityContext().exitFlow();
        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    @Test
    public void testGetEventSchemaType() {

        assertEquals(builder.getEventSchemaType(), Constants.EventSchema.WSO2);
    }

    @Test
    public void testBuildOrganizationCreatedEvent() throws IdentityEventException {

        Organization organization = buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE);
        organization.setAttributes(Arrays.asList(new OrganizationAttribute(ATTRIBUTE_COUNTRY, COUNTRY_USA),
                new OrganizationAttribute(ATTRIBUTE_INDUSTRY, INDUSTRY_CONSTRUCTION)));

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION, organization);

        EventPayload payload = builder.buildOrganizationCreatedEvent(buildEventData(properties));

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2OrganizationCreatedEventPayload);
        WSO2OrganizationCreatedEventPayload createdPayload = (WSO2OrganizationCreatedEventPayload) payload;
        assertEnvelope(createdPayload.getInitiatorType(), createdPayload.getAction(),
                createdPayload.getTenant().getId(), createdPayload.getTenant().getName(),
                createdPayload.getOrganization().getId());

        TargetOrganization targetOrganization = createdPayload.getTargetOrganization();
        assertNotNull(targetOrganization);
        assertEquals(targetOrganization.getId(), ORG_ID);
        assertEquals(targetOrganization.getName(), ORG_NAME);
        assertEquals(targetOrganization.getOrgHandle(), ORG_HANDLE);
        assertEquals(targetOrganization.getDepth(), Integer.valueOf(ORG_DEPTH));
        assertEquals(targetOrganization.getRef(), ORGANIZATIONS_REF_PREFIX + ORG_ID);
        assertNull(targetOrganization.getUpdatedValues());

        assertNotNull(targetOrganization.getAttributes());
        assertNull(targetOrganization.getAttributes().getRemoved());
        assertNull(targetOrganization.getAttributes().getUpdated());
        assertNotNull(targetOrganization.getAttributes().getAdded());
        assertEquals(targetOrganization.getAttributes().getAdded().size(), 2);
        assertEquals(targetOrganization.getAttributes().getAdded().get(0).getName(), ATTRIBUTE_COUNTRY);
        assertEquals(targetOrganization.getAttributes().getAdded().get(0).getValue(), COUNTRY_USA);
        assertEquals(targetOrganization.getAttributes().getAdded().get(1).getName(), ATTRIBUTE_INDUSTRY);
        assertEquals(targetOrganization.getAttributes().getAdded().get(1).getValue(), INDUSTRY_CONSTRUCTION);
    }

    @Test
    public void testBuildOrganizationCreatedEventWithoutAttributes() throws IdentityEventException {

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION, buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE));

        EventPayload payload = builder.buildOrganizationCreatedEvent(buildEventData(properties));

        TargetOrganization targetOrganization =
                ((WSO2OrganizationCreatedEventPayload) payload).getTargetOrganization();
        assertEquals(targetOrganization.getId(), ORG_ID);
        assertNull(targetOrganization.getAttributes());
    }

    @Test
    public void testBuildOrganizationCreatedEventWithBlankAttributeKeyIsSkipped() throws IdentityEventException {

        Organization organization = buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE);
        organization.setAttributes(Arrays.asList(new OrganizationAttribute(" ", COUNTRY_USA),
                new OrganizationAttribute(ATTRIBUTE_REGION, REGION_EMEA)));

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION, organization);

        EventPayload payload = builder.buildOrganizationCreatedEvent(buildEventData(properties));

        TargetOrganization targetOrganization =
                ((WSO2OrganizationCreatedEventPayload) payload).getTargetOrganization();
        assertNotNull(targetOrganization.getAttributes());
        assertEquals(targetOrganization.getAttributes().getAdded().size(), 1);
        assertEquals(targetOrganization.getAttributes().getAdded().get(0).getName(), ATTRIBUTE_REGION);
    }

    @Test
    public void testBuildOrganizationUpdatedEventFromPatchOperations() throws IdentityEventException {

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);
        properties.put(EVENT_PROP_PATCH_OPERATIONS, Arrays.asList(
                new PatchOperation(PATCH_OP_REPLACE, PATCH_PATH_ORG_NAME, UPDATED_NAME),
                new PatchOperation(PATCH_OP_REPLACE, PATCH_PATH_ORG_STATUS, STATUS_DISABLED),
                new PatchOperation(PATCH_OP_ADD, PATCH_PATH_ORG_ATTRIBUTES + ATTRIBUTE_REGION, REGION_EMEA),
                new PatchOperation(PATCH_OP_REMOVE, PATCH_PATH_ORG_ATTRIBUTES + ATTRIBUTE_INDUSTRY, null),
                new PatchOperation(PATCH_OP_REPLACE, PATCH_PATH_ORG_ATTRIBUTES + ATTRIBUTE_COUNTRY, COUNTRY_UK)));

        EventPayload payload = builder.buildOrganizationUpdatedEvent(buildEventData(properties));

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2OrganizationUpdatedEventPayload);
        TargetOrganization targetOrganization =
                ((WSO2OrganizationUpdatedEventPayload) payload).getTargetOrganization();

        // The patch event carries no organization object, so the name and the handle are resolved by id.
        assertEquals(targetOrganization.getId(), ORG_ID);
        assertEquals(targetOrganization.getName(), RESOLVED_ORG_NAME);
        assertEquals(targetOrganization.getOrgHandle(), RESOLVED_ORG_HANDLE);
        assertEquals(targetOrganization.getDepth(), Integer.valueOf(ORG_DEPTH));
        assertEquals(targetOrganization.getRef(), ORGANIZATIONS_REF_PREFIX + ORG_ID);
        assertNull(targetOrganization.getAttributes());

        UpdatedValues updatedValues = targetOrganization.getUpdatedValues();
        assertNotNull(updatedValues);
        assertEquals(updatedValues.getName(), UPDATED_NAME);
        assertEquals(updatedValues.getStatus(), STATUS_DISABLED);
        assertNull(updatedValues.getDescription());
        assertNull(updatedValues.getVersion());

        assertNotNull(updatedValues.getAttributes());
        assertEquals(updatedValues.getAttributes().getAdded().size(), 1);
        assertEquals(updatedValues.getAttributes().getAdded().get(0).getName(), ATTRIBUTE_REGION);
        assertEquals(updatedValues.getAttributes().getAdded().get(0).getValue(), REGION_EMEA);
        assertEquals(updatedValues.getAttributes().getRemoved().size(), 1);
        assertEquals(updatedValues.getAttributes().getRemoved().get(0).getName(), ATTRIBUTE_INDUSTRY);
        assertNull(updatedValues.getAttributes().getRemoved().get(0).getValue());
        assertEquals(updatedValues.getAttributes().getUpdated().size(), 1);
        assertEquals(updatedValues.getAttributes().getUpdated().get(0).getName(), ATTRIBUTE_COUNTRY);
        assertEquals(updatedValues.getAttributes().getUpdated().get(0).getValue(), COUNTRY_UK);
    }

    @Test
    public void testBuildOrganizationUpdatedEventPublishesRemovedFieldAsEmptyValue() throws IdentityEventException {

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);
        properties.put(EVENT_PROP_PATCH_OPERATIONS, Collections.singletonList(
                new PatchOperation(PATCH_OP_REMOVE, PATCH_PATH_ORG_DESCRIPTION, PREVIOUS_DESCRIPTION)));

        EventPayload payload = builder.buildOrganizationUpdatedEvent(buildEventData(properties));

        UpdatedValues updatedValues =
                ((WSO2OrganizationUpdatedEventPayload) payload).getTargetOrganization().getUpdatedValues();
        assertNotNull(updatedValues);
        // A removal clears the field, so the value carried by the request must not be published back.
        assertEquals(updatedValues.getDescription(), "");
        assertNull(updatedValues.getName());
        assertNull(updatedValues.getAttributes());
    }

    @Test
    public void testBuildOrganizationUpdatedEventFromReplacement() throws IdentityEventException {

        Organization previousOrganization = buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE);
        previousOrganization.setDescription(PREVIOUS_DESCRIPTION);
        previousOrganization.setStatus(STATUS_ACTIVE);
        previousOrganization.setAttributes(Arrays.asList(new OrganizationAttribute(ATTRIBUTE_COUNTRY, COUNTRY_USA),
                new OrganizationAttribute(ATTRIBUTE_INDUSTRY, INDUSTRY_CONSTRUCTION)));

        Organization updatedOrganization = buildOrganization(ORG_ID, UPDATED_NAME, ORG_HANDLE);
        updatedOrganization.setDescription(UPDATED_DESCRIPTION);
        updatedOrganization.setStatus(STATUS_ACTIVE);
        updatedOrganization.setAttributes(
                Collections.singletonList(new OrganizationAttribute(ATTRIBUTE_COUNTRY, COUNTRY_UK)));

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);
        properties.put(EVENT_PROP_ORGANIZATION, updatedOrganization);
        properties.put(EVENT_PROP_PREVIOUS_ORGANIZATION, previousOrganization);

        EventPayload payload = builder.buildOrganizationUpdatedEvent(buildEventData(properties));

        TargetOrganization targetOrganization =
                ((WSO2OrganizationUpdatedEventPayload) payload).getTargetOrganization();
        // The replacement carries the organization, so the name and the handle are taken from it.
        assertEquals(targetOrganization.getName(), UPDATED_NAME);
        assertEquals(targetOrganization.getOrgHandle(), ORG_HANDLE);

        UpdatedValues updatedValues = targetOrganization.getUpdatedValues();
        assertNotNull(updatedValues);
        assertEquals(updatedValues.getName(), UPDATED_NAME);
        assertEquals(updatedValues.getDescription(), UPDATED_DESCRIPTION);
        // The status was replaced with the value the organization already held, so it is not a change.
        assertNull(updatedValues.getStatus());

        assertNotNull(updatedValues.getAttributes());
        assertNull(updatedValues.getAttributes().getAdded());
        assertEquals(updatedValues.getAttributes().getUpdated().size(), 1);
        assertEquals(updatedValues.getAttributes().getUpdated().get(0).getName(), ATTRIBUTE_COUNTRY);
        assertEquals(updatedValues.getAttributes().getUpdated().get(0).getValue(), COUNTRY_UK);
        assertEquals(updatedValues.getAttributes().getRemoved().size(), 1);
        assertEquals(updatedValues.getAttributes().getRemoved().get(0).getName(), ATTRIBUTE_INDUSTRY);
    }

    @Test
    public void testBuildOrganizationUpdatedEventWithoutPreviousStateOmitsUpdatedValues()
            throws IdentityEventException {

        Organization updatedOrganization = buildOrganization(ORG_ID, UPDATED_NAME, ORG_HANDLE);
        updatedOrganization.setDescription(UPDATED_DESCRIPTION);

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);
        properties.put(EVENT_PROP_ORGANIZATION, updatedOrganization);

        EventPayload payload = builder.buildOrganizationUpdatedEvent(buildEventData(properties));

        TargetOrganization targetOrganization =
                ((WSO2OrganizationUpdatedEventPayload) payload).getTargetOrganization();
        assertEquals(targetOrganization.getName(), UPDATED_NAME);
        assertNull(targetOrganization.getUpdatedValues());
    }

    @Test
    public void testBuildOrganizationUpdatedEventWithUnchangedReplacementOmitsUpdatedValues()
            throws IdentityEventException {

        Organization previousOrganization = buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE);
        previousOrganization.setDescription(PREVIOUS_DESCRIPTION);
        previousOrganization.setStatus(STATUS_ACTIVE);

        Organization updatedOrganization = buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE);
        updatedOrganization.setDescription(PREVIOUS_DESCRIPTION);
        updatedOrganization.setStatus(STATUS_ACTIVE);

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);
        properties.put(EVENT_PROP_ORGANIZATION, updatedOrganization);
        properties.put(EVENT_PROP_PREVIOUS_ORGANIZATION, previousOrganization);

        EventPayload payload = builder.buildOrganizationUpdatedEvent(buildEventData(properties));

        assertNull(((WSO2OrganizationUpdatedEventPayload) payload).getTargetOrganization().getUpdatedValues());
    }

    @Test
    public void testBuildOrganizationDeletedEventUsesPublishedDepth() throws IdentityEventException {

        Organization deletedOrganization = buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE);

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);
        properties.put(EVENT_PROP_ORGANIZATION, deletedOrganization);
        properties.put(EVENT_PROP_ORGANIZATION_DEPTH_IN_HIERARCHY, PUBLISHED_DELETE_DEPTH);

        EventPayload payload = builder.buildOrganizationDeletedEvent(buildEventData(properties));

        assertNotNull(payload);
        assertTrue(payload instanceof WSO2OrganizationDeletedEventPayload);
        TargetOrganization targetOrganization =
                ((WSO2OrganizationDeletedEventPayload) payload).getTargetOrganization();
        assertEquals(targetOrganization.getId(), ORG_ID);
        assertEquals(targetOrganization.getName(), ORG_NAME);
        assertEquals(targetOrganization.getOrgHandle(), ORG_HANDLE);
        // The depth published with the event is used, since it can no longer be resolved after the deletion.
        assertEquals(targetOrganization.getDepth(), Integer.valueOf(PUBLISHED_DELETE_DEPTH));
        // The management API ref is omitted, since the resource no longer exists.
        assertNull(targetOrganization.getRef());
        assertNull(targetOrganization.getAttributes());
        assertNull(targetOrganization.getUpdatedValues());
    }

    @Test
    public void testBuildOrganizationDeletedEventWithoutOrganization() throws IdentityEventException {

        Map<String, Object> properties = new HashMap<>();
        properties.put(EVENT_PROP_ORGANIZATION_ID, ORG_ID);

        EventPayload payload = builder.buildOrganizationDeletedEvent(buildEventData(properties));

        TargetOrganization targetOrganization =
                ((WSO2OrganizationDeletedEventPayload) payload).getTargetOrganization();
        assertEquals(targetOrganization.getId(), ORG_ID);
        assertNull(targetOrganization.getName());
        assertNull(targetOrganization.getOrgHandle());
        assertNull(targetOrganization.getDepth());
    }

    @Test
    public void testBuildOrganizationCreatedEventWhenOrganizationManagerUnavailable() throws IdentityEventException {

        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(null);
        try {
            Map<String, Object> properties = new HashMap<>();
            properties.put(EVENT_PROP_ORGANIZATION, buildOrganization(ORG_ID, ORG_NAME, ORG_HANDLE));

            EventPayload payload = builder.buildOrganizationCreatedEvent(buildEventData(properties));

            TargetOrganization targetOrganization =
                    ((WSO2OrganizationCreatedEventPayload) payload).getTargetOrganization();
            assertEquals(targetOrganization.getId(), ORG_ID);
            // The depth cannot be resolved without the organization manager, and the event is still built.
            assertNull(targetOrganization.getDepth());
        } finally {
            WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
        }
    }

    private EventData buildEventData(Map<String, Object> properties) {

        EventData eventData = mock(EventData.class);
        when(eventData.getEventParams()).thenReturn(properties);
        return eventData;
    }

    private Organization buildOrganization(String id, String name, String organizationHandle) {

        Organization organization = new Organization();
        organization.setId(id);
        organization.setName(name);
        organization.setOrganizationHandle(organizationHandle);
        return organization;
    }

    private void assertEnvelope(String initiatorType, String action, String tenantId, String tenantName,
                                String contextOrganizationId) {

        assertEquals(initiatorType, TEST_INITIATING_PERSONA.name());
        assertEquals(action, TEST_FLOW_NAME.name());
        assertEquals(tenantId, expectedTenantId);
        assertEquals(tenantName, expectedTenantDomain);
        assertEquals(contextOrganizationId, expectedContextOrganizationId);
    }
}
