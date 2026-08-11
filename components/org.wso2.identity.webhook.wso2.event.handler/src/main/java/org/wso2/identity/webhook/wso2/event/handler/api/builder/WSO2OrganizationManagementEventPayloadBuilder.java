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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementOperation;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.model.Organization;
import org.wso2.carbon.identity.organization.management.service.model.PatchOperation;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementOperationContext;
import org.wso2.identity.webhook.common.event.handler.api.builder.OrganizationManagementEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationCreatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationDeletedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2OrganizationUpdatedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationChange;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.OrganizationRef;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_ORGANIZATION_ID;
import static org.wso2.carbon.identity.organization.management.ext.Constants.EVENT_PROP_PATCH_OPERATIONS;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.ORGANIZATIONS_API_ENDPOINT;

/**
 * WSO2 implementation of OrganizationManagementEventPayloadBuilder.
 */
public class WSO2OrganizationManagementEventPayloadBuilder implements OrganizationManagementEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2OrganizationManagementEventPayloadBuilder.class);

    @Override
    public EventPayload buildOrganizationCreatedEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization organization =
                WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                        IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = resolveInitiatorType(flow);
        String action = resolveAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        Organization newOrganization = extractOrganization(eventData);
        OrganizationRef createdOrganizationRef = (newOrganization != null) ? buildOrganizationRef(newOrganization) :
                buildOrganizationRefWithResolvedDetails(extractOrganizationId(eventData));

        return new WSO2OrganizationCreatedEventPayload.Builder()
                .createdOrganization(createdOrganizationRef)
                .tenant(tenant)
                .organization(organization)
                .initiatorType(initiatorType)
                .initiatorIpAddress(initiatorIpAddress)
                .action(action)
                .build();
    }

    @Override
    public EventPayload buildOrganizationUpdatedEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization organization =
                WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                        IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = resolveInitiatorType(flow);
        String action = resolveAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        /*
         For POST_UPDATE_ORGANIZATION the full organization object is available in the event properties, whereas for
         POST_PATCH_ORGANIZATION only the organization id and the patch operations are present.
        */
        Organization updatedOrganization = extractOrganization(eventData);
        OrganizationRef organizationRef = (updatedOrganization != null) ? buildOrganizationRef(updatedOrganization) :
                buildOrganizationRefWithResolvedDetails(extractOrganizationId(eventData));

        // An update with no patch operations (e.g. a full replace) publishes no changes field at all.
        List<OrganizationChange> changes = buildChanges(extractPatchOperations(eventData));

        return new WSO2OrganizationUpdatedEventPayload.Builder()
                .updatedOrganization(organizationRef)
                .changes(changes.isEmpty() ? null : changes)
                .tenant(tenant)
                .organization(organization)
                .initiatorType(initiatorType)
                .initiatorIpAddress(initiatorIpAddress)
                .action(action)
                .build();
    }

    @Override
    public EventPayload buildOrganizationDeletedEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization organization =
                WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                        IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = resolveInitiatorType(flow);
        String action = resolveAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        /*
         The deleted organization is published in the event properties, since it can no longer be retrieved once the
         deletion is complete. Older versions of the organization management component publish only the id, in which
         case the reference carries the id only.
        */
        Organization deletedOrganization = extractOrganization(eventData);
        OrganizationRef organizationRef = (deletedOrganization != null) ?
                buildDeletedOrganizationRef(deletedOrganization) :
                new OrganizationRef.Builder().id(extractOrganizationId(eventData)).build();

        return new WSO2OrganizationDeletedEventPayload.Builder()
                .deletedOrganization(organizationRef)
                .tenant(tenant)
                .organization(organization)
                .initiatorType(initiatorType)
                .initiatorIpAddress(initiatorIpAddress)
                .action(action)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    /**
     * Resolve the action of the event. A flow already active in the identity context takes precedence, so that an
     * organization operation performed as part of a broader operation reports that operation. When no flow is
     * active, the organization management operation in progress is used.
     *
     * @param flow Flow active in the identity context, if any.
     * @return Action of the event, or null when it cannot be resolved.
     */
    private String resolveAction(Flow flow) {

        if (flow != null) {
            return WSO2PayloadUtils.getFlowAction(flow);
        }
        OrganizationManagementOperation operation = OrganizationManagementOperationContext.getOperation();
        return (operation != null) ? operation.name() : null;
    }

    /**
     * Resolve the initiator type of the event from the active flow, falling back to the actor set in the identity
     * context when no flow is active.
     *
     * @param flow Flow active in the identity context, if any.
     * @return Initiator type of the event, or null when it cannot be resolved.
     */
    private String resolveInitiatorType(Flow flow) {

        if (flow != null) {
            return WSO2PayloadUtils.getFlowInitiatorType(flow);
        }
        IdentityContext identityContext = IdentityContext.getThreadLocalIdentityContext();
        if (identityContext.isApplicationActor()) {
            return Flow.InitiatingPersona.APPLICATION.name();
        } else if (identityContext.isUserActor()) {
            return Flow.InitiatingPersona.ADMIN.name();
        }
        return null;
    }

    private Organization extractOrganization(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_ORGANIZATION);
        return (value instanceof Organization) ? (Organization) value : null;
    }

    private String extractOrganizationId(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_ORGANIZATION_ID);
        return value != null ? value.toString() : null;
    }

    private List<PatchOperation> extractPatchOperations(EventData eventData) {

        Object value = eventData.getEventParams().get(EVENT_PROP_PATCH_OPERATIONS);
        if (!(value instanceof List)) {
            return Collections.emptyList();
        }
        List<PatchOperation> patchOperations = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (item instanceof PatchOperation) {
                patchOperations.add((PatchOperation) item);
            }
        }
        return patchOperations;
    }

    /**
     * Map every patch operation to a change entry, preserving order and keeping operations that target the same
     * field.
     *
     * @param patchOperations Patch operations applied to the organization.
     * @return List of changes, empty when no patch operation is available.
     */
    private List<OrganizationChange> buildChanges(List<PatchOperation> patchOperations) {

        if (patchOperations == null || patchOperations.isEmpty()) {
            return Collections.emptyList();
        }
        List<OrganizationChange> changes = new ArrayList<>(patchOperations.size());
        for (PatchOperation patchOperation : patchOperations) {
            changes.add(new OrganizationChange(patchOperation.getOp(), patchOperation.getPath(),
                    patchOperation.getValue()));
        }
        return changes;
    }

    private OrganizationRef buildOrganizationRef(Organization organization) {

        if (organization == null) {
            return new OrganizationRef.Builder().build();
        }
        String parentId = (organization.getParent() != null) ? organization.getParent().getId() : null;

        return new OrganizationRef.Builder()
                .id(organization.getId())
                .name(organization.getName())
                .description(organization.getDescription())
                .status(organization.getStatus())
                .type(organization.getType())
                .orgHandle(organization.getOrganizationHandle())
                .parentId(parentId)
                .ref(buildOrganizationApiRef(organization.getId()))
                .build();
    }

    /**
     * Build the organization reference for an organization known only by its id, resolving the name and the
     * organization handle from the organization manager. Resolution is best effort: when it fails, the reference is
     * returned with the id and the ref only, so that the event is still published.
     *
     * @param organizationId Id of the organization.
     * @return Organization reference.
     */
    private OrganizationRef buildOrganizationRefWithResolvedDetails(String organizationId) {

        if (organizationId == null) {
            return new OrganizationRef.Builder().build();
        }
        OrganizationRef.Builder builder = new OrganizationRef.Builder()
                .id(organizationId)
                .ref(buildOrganizationApiRef(organizationId));
        OrganizationManager organizationManager =
                WSO2EventHookHandlerDataHolder.getInstance().getOrganizationManager();
        if (organizationManager == null) {
            LOG.debug("Organization manager is not available. Skipping organization detail resolution.");
            return builder.build();
        }
        try {
            builder.name(organizationManager.getOrganizationNameById(organizationId));
            builder.orgHandle(organizationManager.resolveTenantDomain(organizationId));
        } catch (OrganizationManagementException e) {
            LOG.debug("Error while resolving the details of the organization: " + organizationId, e);
        }
        return builder.build();
    }

    /**
     * Build the reference for a deleted organization by removing the fields that are no longer available after
     * the deletion, such as the status and the ref. The name and description are retained.
     *
     * @param organization The organization as it was before the deletion.
     * @return Organization reference.
     */
    private OrganizationRef buildDeletedOrganizationRef(Organization organization) {

        if (organization == null) {
            return new OrganizationRef.Builder().build();
        }
        String parentId = (organization.getParent() != null) ? organization.getParent().getId() : null;

        return new OrganizationRef.Builder()
                .id(organization.getId())
                .name(organization.getName())
                .description(organization.getDescription())
                .type(organization.getType())
                .orgHandle(organization.getOrganizationHandle())
                .parentId(parentId)
                .build();
    }

    private String buildOrganizationApiRef(String organizationId) {

        if (organizationId == null) {
            return null;
        }
        String baseUrl = WSO2PayloadUtils.constructFullURLWithEndpoint(ORGANIZATIONS_API_ENDPOINT);
        return baseUrl + "/" + organizationId;
    }
}
