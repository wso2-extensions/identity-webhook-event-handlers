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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationFailureEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Context;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Reason;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Step;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;

public class WSO2RegistrationEventPayloadBuilder implements RegistrationEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2RegistrationEventPayloadBuilder.class);
    private static final String WSO2_CLAIM_CREATED = "http://wso2.org/claims/created";
    private static final String WSO2_CLAIM_MODIFIED = "http://wso2.org/claims/modified";
    private static final String WSO2_CLAIM_RESOURCE_TYPE = "http://wso2.org/claims/resourceType";
    private static final String WSO2_CLAIM_LOCATION = "http://wso2.org/claims/location";
    private static final String LOCATION_CLAIM = "http://wso2.org/claims/location";

    @Override
    public EventPayload buildRegistrationSuccessEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        User newUser = new User();
        enrichUser(properties, newUser);

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = Optional.ofNullable(resolveAction(flow.getName()))
                    .map(Enum::name)
                    .orElse(null);
        }

        return new WSO2RegistrationSuccessEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .user(newUser)
                .tenant(organization)
                .userStore(userStore)
                .build();
    }

    private void enrichUser(Map<String, Object> properties, User user) {

        if (properties.containsKey(IdentityEventConstants.EventProperty.USER_CLAIMS)) {
            Map<String, String> claims = (Map<String, String>) properties.get(IdentityEventConstants.EventProperty
                    .USER_CLAIMS);

            if (claims.containsKey(FrameworkConstants.USER_ID_CLAIM)) {
                user.setId(claims.get(FrameworkConstants.USER_ID_CLAIM));
                user.setRef(
                        EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + user.getId());
            } else if (claims.containsKey(LOCATION_CLAIM)) {
                user.setRef(claims.get(LOCATION_CLAIM));
                // If the user ID is not set, try to extract it from the ref.
                if (StringUtils.isNotBlank(user.getRef())) {
                    String[] refParts = user.getRef().split("/");
                    if (refParts.length > 0) {
                        user.setId(refParts[refParts.length - 1]);
                    }
                }
            }

            List<UserClaim> filteredUserClaims = filterUserClaimsForUserAdd(claims);
            user.setClaims(filteredUserClaims);
        }
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

    private List<UserClaim> filterUserClaimsForUserAdd(Map<String, String> userClaims) {

        List<UserClaim> userClaimList = new ArrayList<>();
        List<String> excludedClaims = Arrays.asList(
                WSO2_CLAIM_CREATED,
                WSO2_CLAIM_MODIFIED,
                WSO2_CLAIM_RESOURCE_TYPE,
                WSO2_CLAIM_LOCATION,
                FrameworkConstants.USER_ID_CLAIM);

        for (String userClaimUri : userClaims.keySet()) {
            if (!excludedClaims.contains(userClaimUri)) {
                userClaimList.add(new UserClaim(userClaimUri, userClaims.get(userClaimUri)));
            }
        }
        return userClaimList;
    }

    @Override
    public EventPayload buildRegistrationFailureEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        String userStoreDomainName = resolveUserStoreDomain(properties);
        UserStore userStore = null;

        if (StringUtils.isNotBlank(userStoreDomainName)) {
            userStore = new UserStore(userStoreDomainName);
        }

        User newUser = new User();
        enrichUser(properties, newUser);

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = Optional.ofNullable(resolveAction(flow.getName()))
                    .map(Enum::name)
                    .orElse(null);
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

    private RegistrationAction resolveAction(Flow.Name name) {

        if (name == null) {
            return null;
        }

        switch (name) {
            case USER_REGISTRATION:
                return RegistrationAction.REGISTER;
            case USER_REGISTRATION_INVITE_WITH_PASSWORD:
            case INVITED_USER_REGISTRATION:
                return RegistrationAction.INVITE;
            default: {
                log.warn(name + " is not a valid registration action.");
                return null;
            }
        }
    }

    public enum RegistrationAction {
        REGISTER, INVITE
    }

    private String resolveUserStoreDomain(Map<String, Object> properties) {

        if (properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN) != null) {
            return String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
        }
        return null;
    }

}
