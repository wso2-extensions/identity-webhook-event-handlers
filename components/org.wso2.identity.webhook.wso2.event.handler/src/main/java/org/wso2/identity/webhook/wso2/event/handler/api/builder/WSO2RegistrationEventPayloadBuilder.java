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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationFailureEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Context;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Reason;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Step;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Map;

public class WSO2RegistrationEventPayloadBuilder implements RegistrationEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2RegistrationEventPayloadBuilder.class);

    @Override
    public EventPayload buildRegistrationSuccessEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        String userStoreDomainName = WSO2PayloadUtils.resolveUserStoreDomain(properties);
        UserStore userStore = new UserStore(userStoreDomainName);

        User newUser = new User();
        WSO2PayloadUtils.enrichUser(properties, newUser, tenantDomain);

        if (StringUtils.isBlank(newUser.getId())) {

            String userName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_NAME));
            // User set password flow for email invitation by admin.
            newUser = WSO2PayloadUtils.buildUser(userStoreDomainName, userName, tenantDomain);
        }

        String tenantId = null;
        if (properties.get(IdentityEventConstants.EventProperty.TENANT_ID) != null) {
            tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        } else {
            RealmConfiguration realmConfiguration = WSO2PayloadUtils.getRealmConfigurationByTenantDomain(tenantDomain);
            if (realmConfiguration != null)
                tenantId = String.valueOf(realmConfiguration.getTenantId());
        }

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = flow.getName().name();
        }

        return new WSO2RegistrationSuccessEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .user(newUser)
                .tenant(organization)
                .userStore(userStore)
                .build();
    }

    private void addRoles(Map<String, Object> properties, User user) {

        if (!properties.containsKey(IdentityEventConstants.EventProperty.ROLE_LIST)) {
            return;
        }
        String[] roleList = (String[]) properties.get(IdentityEventConstants.EventProperty.ROLE_LIST);

        for (String role : roleList) {
            user.addRole(role);
        }
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    @Override
    public EventPayload buildRegistrationFailureEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        String userStoreDomainName = WSO2PayloadUtils.resolveUserStoreDomain(properties);
        UserStore userStore = null;

        if (StringUtils.isNotBlank(userStoreDomainName)) {
            userStore = new UserStore(userStoreDomainName);
        }

        User newUser = new User();
        WSO2PayloadUtils.enrichUser(properties, newUser, tenantDomain);

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = flow.getName().name();
        }

        String errorMessage = String.valueOf(properties.get(IdentityEventConstants.EventProperty.ERROR_MESSAGE));
        Context context = null;

        if (properties.get(IdentityEventConstants.EventProperty.STEP_ID) != null) {

            String idpName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.IDP));
            String currentAuthenticator =
                    String.valueOf(properties.get(IdentityEventConstants.EventProperty.CURRENT_AUTHENTICATOR));
            int stepId = Integer.parseInt((String) properties.get(IdentityEventConstants.EventProperty.STEP_ID));

            Step failedStep = new Step(stepId, idpName, currentAuthenticator);
            context = new Context(failedStep);

        }

        Reason reason = new Reason(errorMessage, context);

        return new WSO2RegistrationFailureEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .user(newUser)
                .tenant(organization)
                .userStore(userStore)
                .reason(reason)
                .build();
    }
}
