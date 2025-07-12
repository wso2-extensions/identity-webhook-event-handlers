/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Context;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Reason;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Step;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;

/**
 * WSO2 Login Event Payload Builder.
 */
public class WSO2LoginEventPayloadBuilder implements LoginEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2LoginEventPayloadBuilder.class);
    private static final String USERNAME_USER_INPUT = "usernameUserInput";
    private static final String USER = "user";

    @Override
    public EventPayload buildAuthenticationSuccessEvent(EventData eventData) throws IdentityEventException {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        User user = new User();
        WSO2PayloadUtils.populateUserClaims(user, authenticatedUser);
        WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);
        addInitialClaims(user, authenticatedUser);

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain());
        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        Organization b2bUserResidentOrganization = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            b2bUserResidentOrganization = WSO2PayloadUtils.getUserResidentOrganization(
                    authenticatedUser.getUserResidentOrganization());
        }
        Application application = new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName());
        return new WSO2AuthenticationSuccessEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .organization(b2bUserResidentOrganization)
                .userStore(userStore)
                .application(application)
                .authenticationMethods(buildAuthMethods(authenticationContext))
                .build();
    }

    @Override
    public EventPayload buildAuthenticationFailedEvent(EventData eventData) throws IdentityEventException {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = authenticationContext.getSubject();

        User user = new User();
        UserStore userStore = null;

        if (authenticatedUser != null) {
            if (authenticatedUser.getUserStoreDomain() != null) {
                userStore = new UserStore(authenticatedUser.getUserStoreDomain());
            }
            WSO2PayloadUtils.populateUserIdAndRef(user, authenticatedUser);
        }

        if (eventData.getEventParams() != null && eventData.getEventParams()
                .get(USER) instanceof org.wso2.carbon.identity.application.common.model.User) {

            org.wso2.carbon.identity.application.common.model.User failedUser =
                    (org.wso2.carbon.identity.application.common.model.User) eventData.getEventParams().get(USER);

            List<UserClaim> userClaims = user.getClaims();
            if (userClaims == null) {
                userClaims = new ArrayList<>();
            }

            if (StringUtils.isNotBlank(failedUser.getUserName())) {
                Optional<UserClaim>
                        usernameClaimOptional =
                        WSO2PayloadUtils.generateUserClaim(FrameworkConstants.USERNAME_CLAIM, failedUser.getUserName(),
                                failedUser.getTenantDomain());
                usernameClaimOptional.ifPresent(userClaims::add);
                user.setClaims(userClaims);
            }
        }

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain());
        Application application = new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName());
        return new WSO2AuthenticationFailedEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .organization(null)
                .userStore(userStore)
                .application(application)
                .reason(buildAuthenticationFailedReason(authenticationContext))
                .build();
    }

    @Override
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }

    private List<String> buildAuthMethods(AuthenticationContext authContext) {

        List<String> authMethods = new ArrayList<>();
        for (AuthHistory authHistory : authContext.getAuthenticationStepHistory()) {
            authMethods.add(authHistory.toTranslatableString());
            /*
             * For the B2B user scenario, we skip the authentication methods, since it's coming only
             * 'OrganizationAuthenticator`
             */
            if (authHistory.toTranslatableString().equals(Constants.ORGANIZATION_AUTHENTICATOR)) {
                return null;
            }
        }
        return authMethods;
    }

    private Reason buildAuthenticationFailedReason(AuthenticationContext authContext) {

        String errorMessage = resolveErrorMessage(authContext);

        String idp = authContext.getExternalIdP() != null ?
                authContext.getExternalIdP().getIdentityProvider().getIdentityProviderName() : null;
        Step failedStep = new Step(authContext.getCurrentStep(), idp, authContext.getCurrentAuthenticator());
        Context errorContext = new Context(failedStep);

        return new Reason(errorMessage, errorContext);
    }

    private String resolveErrorMessage(AuthenticationContext authContext) {

        HashMap<String, String> dataMap = (HashMap<String, String>) authContext.getParameters().get(Constants.DATA_MAP);

        if (dataMap == null) {
            return null;
        }

        if (dataMap.get(Constants.CURRENT_AUTHENTICATOR_ERROR_MESSAGE) != null) {
            return dataMap.get(Constants.CURRENT_AUTHENTICATOR_ERROR_MESSAGE);
        } else if (dataMap.get(Constants.AUTHENTICATION_ERROR_MESSAGE) != null) {
            return dataMap.get(Constants.AUTHENTICATION_ERROR_MESSAGE);
        }
        return null;
    }

    private void addInitialClaims(User user, AuthenticatedUser authenticatedUser) {

        if (user == null || authenticatedUser == null) {
            return;
        }

        if (user.getClaims() == null) {
            user.setClaims(new ArrayList<>());
        }

        if (StringUtils.isNotBlank(authenticatedUser.getUserName())) {
            user.getClaims().add(WSO2PayloadUtils.generateUserClaim(USERNAME_CLAIM, authenticatedUser.getUserName(),
                    authenticatedUser.getTenantDomain()));
        }
    }
}
