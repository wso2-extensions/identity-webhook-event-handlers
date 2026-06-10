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
import org.wso2.carbon.consent.mgt.core.ConsentManager;
import org.wso2.carbon.consent.mgt.core.exception.ConsentManagementException;
import org.wso2.carbon.consent.mgt.core.model.Purpose;
import org.wso2.carbon.consent.mgt.core.model.PurposePIICategory;
import org.wso2.carbon.consent.mgt.core.model.PurposeVersion;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.ConsentPurposeEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2ConsentPurposeVersionAddedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.PURPOSE_ID;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.PURPOSE_VERSION;
import static org.wso2.carbon.consent.mgt.core.constant.ConsentConstants.SET_AS_LATEST;

/**
 * WSO2 implementation of ConsentPurposeEventPayloadBuilder.
 */
public class WSO2ConsentPurposeEventPayloadBuilder implements ConsentPurposeEventPayloadBuilder {

    private static final Log LOG = LogFactory.getLog(WSO2ConsentPurposeEventPayloadBuilder.class);

    @Override
    public EventPayload buildPurposeVersionAddedEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> params = eventData.getEventParams();

        String purposeId = String.valueOf(params.get(PURPOSE_ID));
        // PurposeVersion here is org.wso2.carbon.consent.mgt.core.model.PurposeVersion (event param)
        PurposeVersion purposeVersion = (PurposeVersion) params.get(PURPOSE_VERSION);
        boolean setAsLatest = Boolean.TRUE.equals(params.get(SET_AS_LATEST));

        String purposeName = resolvePurposeName(purposeId);

        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String action = WSO2PayloadUtils.getFlowAction(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();

        WSO2ConsentPurposeVersionAddedEventPayload.PurposeVersion payloadVersion = null;
        if (purposeVersion != null) {
            List<WSO2ConsentPurposeVersionAddedEventPayload.PurposeElement> elements = new ArrayList<>();
            if (purposeVersion.getPurposePIICategories() != null) {
                for (PurposePIICategory cat : purposeVersion.getPurposePIICategories()) {
                    elements.add(new WSO2ConsentPurposeVersionAddedEventPayload.PurposeElement(
                            cat.getName(), cat.getMandatory()));
                }
            }
            payloadVersion = new WSO2ConsentPurposeVersionAddedEventPayload.PurposeVersion(
                    purposeVersion.getVersion(), setAsLatest, elements.isEmpty() ? null : elements);
        }

        WSO2ConsentPurposeVersionAddedEventPayload.Purpose purpose =
                new WSO2ConsentPurposeVersionAddedEventPayload.Purpose(purposeId, purposeName, payloadVersion);

        return new WSO2ConsentPurposeVersionAddedEventPayload.Builder()
                .purpose(purpose)
                .tenant(tenant)
                .organization(organization)
                .action(action)
                .initiatorType(initiatorType)
                .initiatorIpAddress(initiatorIpAddress)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    private String resolvePurposeName(String purposeId) {

        try {
            ConsentManager consentManager = WSO2EventHookHandlerDataHolder.getInstance().getConsentManager();
            Purpose purpose = consentManager.getPurposeByUuid(purposeId);
            return purpose != null ? purpose.getName() : null;
        } catch (ConsentManagementException e) {
            LOG.warn("Unable to resolve purpose name for id: " + purposeId, e);
            return null;
        }
    }
}
