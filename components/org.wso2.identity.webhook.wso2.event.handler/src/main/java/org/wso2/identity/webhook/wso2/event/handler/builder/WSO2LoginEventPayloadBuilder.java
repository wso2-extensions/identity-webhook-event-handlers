/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.model.AuthenticationFailedReason;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.model.common.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.identity.event.common.publisher.model.EventPayload;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
import static org.wso2.carbon.identity.role.v2.mgt.core.RoleConstants.Error.UNEXPECTED_SERVER_ERROR;
import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;
import static org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils.getReference;

/**
 * WSO2 Login Event Payload Builder.
 */
public class WSO2LoginEventPayloadBuilder implements LoginEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2LoginEventPayloadBuilder.class);
    private Organization b2bUserResidentOrganization;

    @Override
    public EventPayload buildAuthenticationSuccessEvent(EventData eventData) throws IdentityEventException {

        WSO2AuthenticationSuccessEventPayload payload = new WSO2AuthenticationSuccessEventPayload();
        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();

        if (authenticatedUser == null) {
            throw new IdentityEventException("Authenticated user cannot be null.");
        }

        User user = new User();
        try {
            populateUserAttributes(authenticatedUser, user);
            user.setId(authenticatedUser.getUserId());
            user.setRef(getReference(Constants.SCIM2_ENDPOINT, authenticatedUser.getUserId()));
        } catch (UserIdNotFoundException e) {
            throw new IdentityEventException("Error while building the event payload", e);
        }

        payload.setUser(user);
        payload.setUserResidentOrganization(b2bUserResidentOrganization);
        payload.setTenant(new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain()));
        if (authenticatedUser.getUserStoreDomain() != null) {
            payload.setUserStore(new UserStore(authenticatedUser.getUserStoreDomain()));
        }
        payload.setApplication(new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName()));
        payload.setAuthenticationMethods(buildAuthMethods(authenticationContext));

        return payload;
    }

    @Override
    public EventPayload buildAuthenticationFailedEvent(EventData eventData) throws IdentityEventException {

        WSO2AuthenticationFailedEventPayload payload = new WSO2AuthenticationFailedEventPayload();
        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();
        AuthenticatedUser authenticatedUser = authenticationContext.getSubject();

        User user = new User();
        try {
            if (authenticatedUser != null) {
                user.setId(authenticatedUser.getUserId());
                user.setRef(getReference(Constants.SCIM2_ENDPOINT, authenticatedUser.getUserId()));
                payload.setUser(user);
                if (authenticatedUser.getUserStoreDomain() != null) {
                    payload.setUserStore(new UserStore(authenticatedUser.getUserStoreDomain()));
                }
            } else if (eventData.getLoginIdentifier() != null) {
                payload.setUserLoginIdentifier(eventData.getLoginIdentifier().getUserName());
                payload.setUserStore(new UserStore(eventData.getLoginIdentifier().getUserStoreDomain()));
            }
        } catch (UserIdNotFoundException e) {
            throw new IdentityEventException("Error while building the event payload", e);
        }

        payload.setTenant(new Organization(
                String.valueOf(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain())),
                authenticationContext.getTenantDomain()));
        payload.setApplication(new Application(
                authenticationContext.getServiceProviderResourceId(),
                authenticationContext.getServiceProviderName()));
        payload.setReason(buildAuthenticationFailedReason(authenticationContext));

        return payload;
    }

    @Override
    public String getEventSchemaType() {
        return EVENT_SCHEMA_TYPE_WSO2;
    }

    private List<String> buildAuthMethods(AuthenticationContext authContext) {

        List<String> authMethods = new ArrayList<>();
        for (AuthHistory authHistory : authContext.getAuthenticationStepHistory()) {
            authMethods.add(authHistory.toTranslatableString());
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

    private void populateUserAttributes(AuthenticatedUser authenticatedUser, User user) throws IdentityEventException {

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
                    case Constants.USER_ORGANIZATION:
                        setUserOrganization(claimValue);
                        break;
                    default:
                        userClaims.add(new UserClaim(claimUri, claimValue));
                        break;
                }
            }
        }
        user.setClaims(userClaims);
    }

    private void setUserOrganization(String claimValue) throws IdentityEventException {

        try {
            String organizationName = WSO2EventHookHandlerDataHolder.getInstance()
                    .getOrganizationManager().getOrganizationNameById(claimValue);
            b2bUserResidentOrganization = new Organization(claimValue, organizationName);
        } catch (OrganizationManagementException e) {
            if (ERROR_CODE_INVALID_ORGANIZATION_ID.getCode().equals(e.getErrorCode())) {
                log.debug("Returning an empty string as the organization name as the name is not returned for the given id.");
            }
            throw new IdentityEventException(UNEXPECTED_SERVER_ERROR.getCode(),
                    "Error while retrieving the organization name for the given id.", e);
        }
    }
}
