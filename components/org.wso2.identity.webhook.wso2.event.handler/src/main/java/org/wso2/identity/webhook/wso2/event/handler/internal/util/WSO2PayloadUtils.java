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

package org.wso2.identity.webhook.wso2.event.handler.internal.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;

public class WSO2PayloadUtils {

    private static final Log log = LogFactory.getLog(WSO2PayloadUtils.class);

    public static Organization getUserResidentOrganization(String organizationId) {

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

    public static void populateUserClaims(User user, AuthenticatedUser authenticatedUser) {

        if (authenticatedUser == null || authenticatedUser.getUserAttributes() == null) {
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

    public static void populateUserIdAndRef(User user, AuthenticatedUser authenticatedUser) {

        try {
            user.setId(authenticatedUser.getUserId());
            user.setRef(EventPayloadUtils.constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT) +
                    "/" + authenticatedUser.getUserId());
        } catch (UserIdNotFoundException e) {
            //TODO: Need to verify when this exception is thrown and handle it accordingly
            log.debug("Error while resolving user id.", e);
        }
    }

    /**
     * Retrieves the UserStoreManager for the given tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @return The UserStoreManager for the specified tenant domain, or null if not found.
     */
    public static UserStoreManager getUserStoreManagerByTenantDomain(String tenantDomain) {

        try {
            UserRealm userRealm = getUserRealm(tenantDomain);
            if (userRealm == null) return null;

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            if (userStoreManager == null) {
                if (log.isDebugEnabled()) {
                    log.debug("UserStoreManager is null for tenant: " + tenantDomain);
                }
                return null;
            }
            return userStoreManager;

        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while retrieving user store manager for tenant: " +
                        tenantDomain + ". Error: " + e.getMessage(), e);
            }
        }

        return null;
    }

    /**
     * Retrieves the RealmConfiguration for the given tenant domain.
     *
     * @param tenantDomain The tenant domain.
     * @return The RealmConfiguration for the specified tenant domain, or null if not found.
     */
    public static RealmConfiguration getRealmConfigurationByTenantDomain(String tenantDomain) {

        try {
            UserRealm userRealm = getUserRealm(tenantDomain);
            if (userRealm == null) return null;

            return userRealm.getRealmConfiguration();

        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while retrieving user store manager for tenant: " +
                        tenantDomain + ". Error: " + e.getMessage(), e);
            }
        }

        return null;
    }

    private static UserRealm getUserRealm(String tenantDomain) throws UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        RealmService realmService = WSO2EventHookHandlerDataHolder.getInstance().getRealmService();

        if (realmService == null) {
            if (log.isDebugEnabled()) {
                log.debug("RealmService is not available. Skipping setting user store manager.");
            }
            return null;
        }

        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
        if (userRealm == null) {
            if (log.isDebugEnabled()) {
                log.debug("UserRealm is null for tenant: " + tenantId);
            }
            return null;
        }
        return userRealm;
    }

    /**
     * Resolve the event metadata based on the event name.
     *
     * @param eventName Event name.
     * @return Event metadata containing event and channel information.
     */
    public static EventMetadata resolveEventHandlerKey(String eventName) {

        String event = null;
        String channel = null;
        if (Objects.requireNonNull(eventName).equals(
                IdentityEventConstants.Event.AUTHENTICATION_SUCCESS)) {
            channel = org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.LOGIN_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.LOGIN_SUCCESS_EVENT;
        } else if (IdentityEventConstants.Event.AUTHENTICATION_STEP_FAILURE.equals(eventName)) {
            channel = org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.LOGIN_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.LOGIN_FAILURE_EVENT;
        } else if (IdentityEventConstants.Event.USER_SESSION_TERMINATE.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_REVOKED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_EXPIRE.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_EXPIRED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_UPDATE.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_UPDATED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_EXTEND.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_EXTENDED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_CREATE.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_CREATED_EVENT;
        } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_LIST_OF_ROLE_EVENT;
        } else if (IdentityEventConstants.Event.POST_DELETE_USER.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_DELETE_USER_EVENT;
        } else if (IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UNLOCK_ACCOUNT_EVENT;
        } else if (IdentityEventConstants.Event.POST_LOCK_ACCOUNT.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_LOCK_ACCOUNT_EVENT;
        } else if (IdentityEventConstants.Event.POST_USER_PROFILE_UPDATE.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_PROFILE_UPDATED_EVENT;
        } else if (isCredentialUpdateFlow(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CREDENTIAL_CHANGE_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_CREDENTIAL;
        } else if (isUserRegistrationSuccessFlow(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.REGISTRATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_REGISTRATION_SUCCESS_EVENT;
        } else if (isUserRegistrationFailedFlow(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.REGISTRATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_REGISTRATION_FAILED_EVENT;
        }
        return EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(WSO2.name())
                .build();
    }

    private static boolean isUserRegistrationSuccessFlow(String eventName) {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;

        return (IdentityEventConstants.Event.POST_ADD_USER.equals(eventName) &&
                !Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD.equals(flowName)) ||
                (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName) &&
                        Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD.equals(flowName)) ||
                IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM.equals(eventName) ||
                IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS.equals(eventName);
    }

    private static boolean isUserRegistrationFailedFlow(String eventName) {

        return IdentityEventConstants.Event.USER_REGISTRATION_FAILED.equals(eventName);
    }

    private static boolean isCredentialUpdateFlow(String eventName) {

        if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName)) {
            Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
            Flow.Name flowName = (flow != null) ? flow.getName() : null;

            return !Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD.equals(flowName);
        }

        return IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName);
    }
}
