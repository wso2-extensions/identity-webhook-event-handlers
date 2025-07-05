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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.exception.ClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.model.LocalClaim;
import org.wso2.carbon.identity.claim.metadata.mgt.util.ClaimConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.CREATED_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.LOCATION_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.MODIFIED_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.RESOURCE_TYPE_CLAIM;

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
                    case Constants.GROUPS_CLAIM:
                        user.addGroup(claimValue);
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
                        userClaims.add(generateUserClaim(claimUri, claimValue, authenticatedUser.getTenantDomain()));
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
    private static UserStoreManager getUserStoreManagerByTenantDomain(String tenantDomain) {

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
        } else if (IdentityEventConstants.Event.POST_ENABLE_ACCOUNT.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ACCOUNT_ENABLE_EVENT;
        } else if (IdentityEventConstants.Event.POST_DISABLE_ACCOUNT.equals(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ACCOUNT_DISABLE_EVENT;
        } else if (isCredentialUpdateFlow(eventName)) {
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CREDENTIAL_CHANGE_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_CREDENTIAL;
        } else if (isUserCreatedFlow(eventName)) {
            /*
            The user operation check must always precede the registration check, since user creation occurs before
            registration, and both events are triggered by the same event: POST_ADD_USER.
            // TODO this issue is due to sequence utility access of metadata.
             */
            channel =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
            event =
                    org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_CREATED_EVENT;
        } // TODO Temporary removing until refactoring the metadata resolving.
        return EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(WSO2.name())
                .build();
    }

    private static boolean isUserRegistrationSuccessFlow(String eventName) {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;

        /*
        Event.POST_ADD_USER + Flow.Name.USER_REGISTRATION:
            Direct user registration, initiated either by an admin or the user.

        Event.POST_ADD_NEW_PASSWORD + Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD:
            User completes registration after being invited by an admin.

        Event.POST_SELF_SIGNUP_CONFIRM:
            Self-signup flow completed by the user.

        IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS:
            Registration via Just-In-Time (JIT) provisioning or the new registration orchestration flow.
         */
        return (IdentityEventConstants.Event.POST_ADD_USER.equals(eventName) &&
                Flow.Name.USER_REGISTRATION.equals(flowName)) ||
                IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM.equals(eventName) ||
                IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS.equals(eventName) ||
                (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName) &&
                        Flow.Name.USER_REGISTRATION_INVITE_WITH_PASSWORD.equals(flowName));
    }

    private static boolean isUserRegistrationFailedFlow(String eventName) {

        return IdentityEventConstants.Event.USER_REGISTRATION_FAILED.equals(eventName);
    }

    private static boolean isUserCreatedFlow(String eventName) {

        /*
        All POST_ADD_USER events will result in a userCreated event payload.
        Since user creation does not imply successful registration,
        this check is valid and does not cause any issues.
         */
        return (IdentityEventConstants.Event.POST_ADD_USER.equals(eventName) ||
                IdentityEventConstants.Event.USER_REGISTRATION_SUCCESS.equals(eventName));
    }

    private static boolean isCredentialUpdateFlow(String eventName) {

        /*
        Event.POST_ADD_NEW_PASSWORD + Flow.Name.PASSWORD_RESET:
            Triggered when a user resets their password, either:
                After an admin-enforced password reset, or
                Through the "Forgot Password" flow.

        Event.POST_UPDATE_CREDENTIAL_BY_SCIM:
            Triggered when:
                A user resets their password via the My Account portal, or
                An admin resets the user's password via the Console.
         */
        if (IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName)) {
            Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
            Flow.Name flowName = (flow != null) ? flow.getName() : null;

            return Flow.Name.PASSWORD_RESET.equals(flowName);
        }

        return IdentityEventConstants.Event.POST_UPDATE_CREDENTIAL_BY_SCIM.equals(eventName);
    }

    public static UserClaim generateUserClaim(String claimKey, String claimValue, String tenantDomain) {

        UserClaim.Builder userClaimBuilder = new UserClaim.Builder()
                .uri(claimKey);

        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();
        if (isMultiValuedClaim(claimKey, tenantDomain)) {
            userClaimBuilder.value(StringUtils.isBlank(claimValue) ? new String[]{} :
                    claimValue.split(Pattern.quote(multiAttributeSeparator)));
        } else {
            userClaimBuilder.value(claimValue);
        }

        return userClaimBuilder.build();
    }

    private static boolean isMultiValuedClaim(String claimUri, String tenantDomain) {

        ClaimMetadataManagementService claimMetadataManagementService =
                WSO2EventHookHandlerDataHolder.getInstance().getClaimMetadataManagementService();

        try {
            Optional<LocalClaim>
                    localClaim = claimMetadataManagementService.getLocalClaim(claimUri, tenantDomain);

            if (localClaim.isPresent()) {
                return Boolean.parseBoolean(localClaim.get().getClaimProperty(ClaimConstants.MULTI_VALUED_PROPERTY));
            }

        } catch (ClaimMetadataException e) {
            log.error("Error while retrieving claim metadata for claim URI: " + claimUri, e);
        }
        return false;
    }

    public static void enrichUser(UserStoreManager userStoreManager, String domainQualifiedUserName, User user,
                                  String tenantDomain)
            throws IdentityEventException {

        String userId;
        try {
            userId = userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.USER_ID_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
            user.setId(userId);

            String emailAddress =
                    userStoreManager.getUserClaimValue(domainQualifiedUserName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                            UserCoreConstants.DEFAULT_PROFILE);
            UserClaim emailAddressUserClaim =
                    generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress,
                            tenantDomain);
            List<UserClaim> userClaims = new ArrayList<>();
            userClaims.add(emailAddressUserClaim);

            user.setClaims(userClaims);

        } catch (UserStoreException e) {
            throw new IdentityEventException(
                    "Error while extracting user claims for the user : " + domainQualifiedUserName, e);
        }
    }

    public static User buildUser(String userStoreDomain, String userName, String tenantDomain)
            throws IdentityEventException {

        UserStoreManager userStoreManager = getUserStoreManagerByTenantDomain(tenantDomain);
        User user = new User();
        if (userStoreManager != null) {
            String domainQualifiedUserName = userStoreDomain + "/" + userName;
            WSO2PayloadUtils.enrichUser(userStoreManager, domainQualifiedUserName, user, tenantDomain);
            user.setRef(EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + user.getId());
        }
        return user;
    }

    public static String resolveUserStoreDomain(Map<String, Object> properties) {

        String userStoreDomainName = null;
        if (properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN) != null) {
            userStoreDomainName =
                    String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));
        }
        if (StringUtils.isBlank(userStoreDomainName) &&
                properties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER) != null) {

            Object userStoreManagerObj = properties.get(IdentityEventConstants.EventProperty.USER_STORE_MANAGER);
            if (userStoreManagerObj instanceof AbstractUserStoreManager) {
                AbstractUserStoreManager userStoreManager =
                        (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);

                userStoreDomainName = userStoreManager.getRealmConfiguration()
                        .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
            }
        }
        return userStoreDomainName;
    }

    public static List<UserClaim> filterUserClaimsForUserAdd(Map<String, String> userClaims, String tenantDomain) {

        List<UserClaim> userClaimList = new ArrayList<>();
        List<String> excludedClaims = Arrays.asList(
                CREATED_CLAIM,
                MODIFIED_CLAIM,
                RESOURCE_TYPE_CLAIM,
                LOCATION_CLAIM,
                FrameworkConstants.USER_ID_CLAIM);

        for (String userClaimUri : userClaims.keySet()) {
            if (!excludedClaims.contains(userClaimUri)) {
                userClaimList.add(
                        generateUserClaim(userClaimUri, userClaims.get(userClaimUri),
                                tenantDomain));
            }
        }
        return userClaimList;
    }

    public static void enrichUser(Map<String, Object> properties, User user, String tenantDomain) {

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

            List<UserClaim> filteredUserClaims = filterUserClaimsForUserAdd(claims, tenantDomain);
            user.setClaims(filteredUserClaims);
        }
    }
}
