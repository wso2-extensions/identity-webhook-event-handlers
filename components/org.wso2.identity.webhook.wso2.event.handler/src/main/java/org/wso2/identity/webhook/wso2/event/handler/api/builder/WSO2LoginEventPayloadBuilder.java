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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.AuthenticationFailedReason;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.service.WSO2EventHookHandlerDataHolder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
import static org.wso2.identity.webhook.common.event.handler.api.constant.Constants.WSO2_EVENT_SCHEMA;
import static org.wso2.identity.webhook.common.event.handler.api.constant.Constants.ORGANIZATION_AUTHENTICATOR;

/**
 * WSO2 Login Event Payload Builder.
 */
public class WSO2LoginEventPayloadBuilder implements LoginEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2LoginEventPayloadBuilder.class);

    @Override
    public EventPayload buildAuthenticationSuccessEvent(EventData eventData) throws IdentityEventException {

        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        User user = new User();
        populateUserAttributes(authenticatedUser, user);
        try {
            user.setId(authenticatedUser.getUserId());
            user.setRef(EventHookHandlerUtils.getInstance().constructFullURLWithEndpoint(Constants.SCIM2_ENDPOINT) +
                    "/" + authenticatedUser.getUserId());
        } catch (UserIdNotFoundException e) {
            //TODO: Need to verify when this exception is thrown and handle it accordingly
            log.debug("Error while resolving user id.", e);
        }

        Organization tenant = new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain());
        UserStore userStore = null;
        if (authenticatedUser.getUserStoreDomain() != null) {
            userStore = new UserStore(authenticatedUser.getUserStoreDomain());
        }
        Organization b2bUserResidentOrganization = null;
        if (authenticatedUser.getUserResidentOrganization() != null) {
            b2bUserResidentOrganization = getUserResidentOrganization(
                    authenticatedUser.getUserResidentOrganization());
        }
        Application application = new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName());
        return new WSO2AuthenticationSuccessEventPayload.Builder()
                .user(user)
                .tenant(tenant)
                .userResidentOrganization(b2bUserResidentOrganization)
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
            try {
            user.setId(authenticatedUser.getUserId());
            user.setRef(EventHookHandlerUtils.getInstance().constructFullURLWithEndpoint(Constants.SCIM2_ENDPOINT)
                    + "/" + authenticatedUser.getUserId());
            } catch (UserIdNotFoundException e) {
            //TODO: Need to verify when this exception is thrown and handle it accordingly
            log.debug("Error while resolving user id.", e);
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
                .userResidentOrganization(null)
                .userStore(userStore)
                .application(application)
                .reason(buildAuthenticationFailedReason(authenticationContext))
                .build();
    }

    @Override
    public String getEventSchemaType() {
        return WSO2_EVENT_SCHEMA;
    }

    private List<String> buildAuthMethods(AuthenticationContext authContext) {

        List<String> authMethods = new ArrayList<>();
        for (AuthHistory authHistory : authContext.getAuthenticationStepHistory()) {
            authMethods.add(authHistory.toTranslatableString());
            /*
             * For the B2B user scenario, we skip the authentication methods, since it's coming only
             * 'OrganizationAuthenticator`
             */
            if (authHistory.toTranslatableString().equals(ORGANIZATION_AUTHENTICATOR)) {
                return null;
            }
        }
        return authMethods;
    }

    private AuthenticationFailedReason buildAuthenticationFailedReason(AuthenticationContext authContext) {

        AuthenticationFailedReason failedReason = new AuthenticationFailedReason();
        HashMap<String, String> dataMap = (HashMap<String, String>) authContext.getParameters().get(Constants.DATA_MAP);
        String errorCode = dataMap.get(Constants.CURRENT_AUTHENTICATOR_ERROR_CODE);
        failedReason.setId(errorCode);

        AuthenticationFailedReason.FailedStep failedStep = new AuthenticationFailedReason.FailedStep();
        failedStep.setStep(authContext.getCurrentStep());
        failedStep.setAuthenticator(authContext.getCurrentAuthenticator());
        failedStep.setIdp(authContext.getExternalIdP() != null ?
                authContext.getExternalIdP().getIdentityProvider().getIdentityProviderName() : null);
        failedReason.setFailedStep(failedStep);

        return failedReason;
    }

    private void populateUserAttributes(AuthenticatedUser authenticatedUser, User user) {

        if (authenticatedUser == null) {
            return;
        }

        List<UserClaim> userClaims = new ArrayList<>();
        for (Map.Entry<ClaimMapping, String> entry : authenticatedUser.getUserAttributes().entrySet()) {
            ClaimMapping claimMapping = entry.getKey();
            String claimUri = claimMapping.getLocalClaim().getClaimUri();
            String claimValue = entry.getValue();

            if (claimUri != null && claimValue != null) {
                switch (claimUri) {
                    case Constants.WSO2_CLAIM_GROUPS:
                        user.addGroup(claimValue);
                        break;
                    case Constants.WSO2_CLAIM_ROLES:
                        user.addRole(claimValue);
                        break;
                    case Constants.MULTI_ATTRIBUTE_SEPARATOR:
                        // Not adding the multi attribute separator to the user claims
                        break;
                    case Constants.IDENTITY_PROVIDER_MAPPED_USER_ROLES:
                        // Not adding the identity provider mapped user roles to the user claims for federated users
                        break;
                    case Constants.USER_ORGANIZATION:
                        // Not adding the user resident organization to the user claims for b2b users
                        break;
                    default:
                        userClaims.add(new UserClaim(claimUri, claimValue));
                        break;
                }
            }
        }
        user.setClaims(userClaims);
    }

    private Organization getUserResidentOrganization(String organizationId) {

        try {
            String organizationName = WSO2EventHookHandlerDataHolder.getInstance()
                    .getOrganizationManager().getOrganizationNameById(organizationId);
            return new Organization(organizationId, organizationName);
        } catch (OrganizationManagementException e) {
            if (ERROR_CODE_INVALID_ORGANIZATION_ID.getCode().equals(e.getErrorCode())) {
                log.debug("Returning an empty string as the organization name as the name is not returned " +
                        "for the given id.");
            }
            log.debug("Error while retrieving the organization name for the given id: " + organizationId, e);
        }
        return null;
    }
}
