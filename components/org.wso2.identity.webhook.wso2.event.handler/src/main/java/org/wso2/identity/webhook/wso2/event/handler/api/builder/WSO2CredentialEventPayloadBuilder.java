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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserCredentialUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Map;

public class WSO2CredentialEventPayloadBuilder implements CredentialEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2CredentialEventPayloadBuilder.class);

    @Override
    public EventPayload buildCredentialUpdateEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());
        String userName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_NAME));
        String userStoreDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));

        User user = WSO2PayloadUtils.buildUser(userStoreDomain, userName, accessedTenantDomain);

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);
        UserStore userStore = new UserStore(userStoreDomain);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String action = null;
        String initiatorType = null;
        String credentialType = null;

        if (flow != null) {
            action = flow.getName().name();
            initiatorType = flow.getInitiatingPersona().name();

            if (Flow.isCredentialFlow(flow.getName())) {
                credentialType = flow.getCredentialType().name();
            }
        }
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

        return new WSO2UserCredentialUpdateEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .credentialType(credentialType)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }
}
