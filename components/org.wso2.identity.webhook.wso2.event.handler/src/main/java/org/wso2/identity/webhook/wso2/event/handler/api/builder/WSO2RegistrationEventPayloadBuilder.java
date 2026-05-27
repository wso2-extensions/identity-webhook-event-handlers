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
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationFailureEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Context;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Reason;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Step;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Map;
import java.util.Optional;

public class WSO2RegistrationEventPayloadBuilder implements RegistrationEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2RegistrationEventPayloadBuilder.class);

    /**
     * Helper class to hold common registration event context.
     */
    private static class RegistrationEventContext {
        final Tenant tenant;
        final User user;
        final UserStore userStore;
        final String initiatorType;
        final String initiatorIpAddress;
        final String action;
        final Organization organization;

        RegistrationEventContext(Tenant tenant, User user, UserStore userStore, String initiatorType,
                                 String initiatorIpAddress, String action, Organization organization) {
            this.tenant = tenant;
            this.user = user;
            this.userStore = userStore;
            this.initiatorType = initiatorType;
            this.initiatorIpAddress = initiatorIpAddress;
            this.action = action;
            this.organization = organization;
        }
    }

    @Override
    public EventPayload buildRegistrationSuccessEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        String userStoreDomainName = WSO2PayloadUtils.resolveUserStoreDomain(properties);
        UserStore userStore = new UserStore(userStoreDomainName);

        User newUser = new User();
        WSO2PayloadUtils.enrichUser(properties, newUser, accessedTenantDomain);

        if (StringUtils.isBlank(newUser.getId())) {

            String userName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_NAME));
            // User set password flow for email invitation by admin.
            newUser = WSO2PayloadUtils.buildUser(userStoreDomainName, userName, accessedTenantDomain);
        }

        RegistrationEventContext context = buildRegistrationEventContext(properties, newUser, userStore);

        return new WSO2RegistrationSuccessEventPayload.Builder()
                .initiatorType(context.initiatorType)
                .action(context.action)
                .user(context.user)
                .tenant(context.tenant)
                .organization(context.organization)
                .userStore(context.userStore)
                .initiatorIpAddress(context.initiatorIpAddress)
                .build();
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    /**
     * Builds common registration event context from properties and user data.
     *
     * @param properties the event properties
     * @param user the user object
     * @param userStore the user store object
     * @return the registration event context
     */
    private RegistrationEventContext buildRegistrationEventContext(Map<String, Object> properties, User user,
                                                                    UserStore userStore) {

        String rootTenantId = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantId());
        String rootTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getRootOrganization().getAssociatedTenantDomain());

        Tenant tenant = new Tenant(rootTenantId, rootTenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = WSO2PayloadUtils.getFlowInitiatorType(flow);
        String initiatorIpAddress = WSO2PayloadUtils.resolveInitiatorIpAddress();
        String action = null;
        if (flow != null) {
            action = Optional.ofNullable(resolveAction(flow.getName()))
                    .map(Enum::name)
                    .orElse(null);
        }
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        user.setOrganization(organization);

         return new RegistrationEventContext(tenant, user, userStore, initiatorType, initiatorIpAddress, action,
                 organization);
     }

     @Override
     public EventPayload buildRegistrationFailureEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String accessedTenantDomain = String.valueOf(
                IdentityContext.getThreadLocalIdentityContext().getOrganization().getOrganizationHandle());

        String userStoreDomainName = WSO2PayloadUtils.resolveUserStoreDomain(properties);
        UserStore userStore = null;

        if (StringUtils.isNotBlank(userStoreDomainName)) {
            userStore = new UserStore(userStoreDomainName);
        }

        User newUser = new User();
        WSO2PayloadUtils.enrichUser(properties, newUser, accessedTenantDomain);

        RegistrationEventContext context = buildRegistrationEventContext(properties, newUser, userStore);

        String errorMessage = String.valueOf(properties.get(IdentityEventConstants.EventProperty.ERROR_MESSAGE));
        Context failureContext = null;

        if (properties.get(IdentityEventConstants.EventProperty.STEP_ID) != null) {

            String idpName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.IDP));
            String currentAuthenticator =
                    String.valueOf(properties.get(IdentityEventConstants.EventProperty.CURRENT_AUTHENTICATOR));
            int stepId = Integer.parseInt((String) properties.get(IdentityEventConstants.EventProperty.STEP_ID));

            Step failedStep = new Step(stepId, idpName, currentAuthenticator);
            failureContext = new Context(failedStep);

        }

         Reason reason = new Reason(errorMessage, failureContext);

         return new WSO2RegistrationFailureEventPayload.Builder()
                 .initiatorType(context.initiatorType)
                 .action(context.action)
                 .user(context.user)
                 .tenant(context.tenant)
                 .organization(context.organization)
                 .userStore(context.userStore)
                 .reason(reason)
                 .initiatorIpAddress(context.initiatorIpAddress)
                 .build();
     }

     private RegistrationAction resolveAction(Flow.Name name) {

         if (name == null) {
             return null;
         }

         switch (name) {
             case REGISTER:
                 return RegistrationAction.REGISTER;
             case INVITE:
             case INVITED_USER_REGISTRATION:
                 return RegistrationAction.INVITE;
             case JUST_IN_TIME_PROVISION:
                 return RegistrationAction.JUST_IN_TIME_PROVISION;
             default: {
                 log.debug(name + " is not a valid registration action.");
                 return null;
             }
         }
     }

     public enum RegistrationAction {
         REGISTER, INVITE, JUST_IN_TIME_PROVISION
     }

 }
