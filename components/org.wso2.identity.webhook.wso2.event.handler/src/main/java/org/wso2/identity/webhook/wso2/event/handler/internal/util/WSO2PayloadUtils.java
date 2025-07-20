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
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
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

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.CREDENTIAL_CHANGE_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.LOGIN_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.SESSION_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Channel.USER_OPERATION_CHANNEL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.LOGIN_FAILURE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.LOGIN_SUCCESS_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ACCOUNT_DISABLE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_ACCOUNT_ENABLE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_DELETE_USER_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_LOCK_ACCOUNT_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UNLOCK_ACCOUNT_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_CREDENTIAL;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_UPDATE_USER_LIST_OF_ROLE_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_CREATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.POST_USER_PROFILE_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_CREATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_EXPIRED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_EXTENDED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_REVOKED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.Event.SESSION_UPDATED_EVENT;
import static org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.CREATED_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.EMAIL_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.LOCATION_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.MODIFIED_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.RESOURCE_TYPE_CLAIM;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.USERNAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.WSO2_CLAIM_URI_PREFIX;

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

    public static void populateUserClaims(User user, AuthenticatedUser authenticatedUser, String tenantDomain) {

        if (authenticatedUser == null) {
            return;
        }

        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
        if (userAttributes != null) {
            userAttributes.forEach((claimMapping, claimValue) -> {
                if (isValidClaim(claimMapping, claimValue)) {
                    String claimUri = claimMapping.getLocalClaim().getClaimUri();
                    handleClaim(user, claimUri, claimValue, tenantDomain);
                }
            });
        }

        if (shouldAddUsernameClaim(user, authenticatedUser)) {
            Optional<UserClaim> userNameClaimOptional = generateUserClaim(
                    USERNAME_CLAIM, authenticatedUser.getUserName(), authenticatedUser.getTenantDomain());
            userNameClaimOptional.ifPresent(user::addClaim);
        }
    }

    private static boolean isValidClaim(ClaimMapping claimMapping, String claimValue) {

        return claimMapping != null &&
                claimMapping.getLocalClaim() != null &&
                StringUtils.isNotBlank(claimMapping.getLocalClaim().getClaimUri()) &&
                StringUtils.isNotBlank(claimValue) &&
                claimMapping.getLocalClaim().getClaimUri().startsWith(WSO2_CLAIM_URI_PREFIX);
    }

    private static boolean shouldAddUsernameClaim(User user, AuthenticatedUser authenticatedUser) {

        return StringUtils.isNotBlank(authenticatedUser.getUserName()) &&
                (user.getClaims() == null ||
                        user.getClaims().stream().noneMatch(claim -> USERNAME_CLAIM_URI.equals(claim.getUri())));
    }

    public static void populateUserClaims(User user, String userId, String tenantDomain) {

        UserStoreManager userStoreManager = getUserStoreManagerByTenantDomain(tenantDomain);
        if (!(userStoreManager instanceof AbstractUserStoreManager)) {
            return;
        }

        Map<String, String> claimValues;
        try {
            claimValues = ((AbstractUserStoreManager) userStoreManager).getUserClaimValuesWithID(
                    userId, new String[]{USERNAME_CLAIM_URI, EMAIL_CLAIM_URI}, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            log.error("Error while retrieving user claims for user: " + userId + " in tenant: " + tenantDomain, e);
            return;
        }

        if (claimValues == null || claimValues.isEmpty()) {
            return;
        }

        claimValues.forEach((claimUri, claimValue) -> {
            if (isValidClaim(claimUri, claimValue)) {
                handleClaim(user, claimUri, claimValue, tenantDomain);
            }
        });
    }

    private static boolean isValidClaim(String claimUri, String claimValue) {

        return StringUtils.isNotBlank(claimUri) &&
                StringUtils.isNotBlank(claimValue) &&
                claimUri.startsWith(WSO2_CLAIM_URI_PREFIX);
    }

    public static void populateUserIdAndRef(User user, String userId) {

        user.setId(userId);
        user.setRef(constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT) + "/" + userId);
    }

    private static void handleClaim(User user, String claimUri, String claimValue, String tenantDomain) {

        switch (claimUri) {
            case Constants.GROUPS_CLAIM:
                user.addGroup(claimValue);
                break;
            case Constants.MULTI_ATTRIBUTE_SEPARATOR:
            case Constants.IDENTITY_PROVIDER_MAPPED_USER_ROLES:
            case Constants.USER_ORGANIZATION:
                // Skip these claims
                break;
            default:
                Optional<UserClaim> userClaimOptional = generateUserClaim(claimUri, claimValue, tenantDomain);
                userClaimOptional.ifPresent(user::addClaim);
                break;
        }
    }

    public static void populateUserIdAndRef(User user, AuthenticatedUser authenticatedUser) {

        try {
            user.setId(authenticatedUser.getUserId());
            user.setRef(constructFullURLWithEndpoint(Constants.SCIM2_USERS_ENDPOINT) +
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

        if (!isBulkOperation()) {
            if (Objects.requireNonNull(eventName).equals(
                    IdentityEventConstants.Event.AUTHENTICATION_SUCCESS)) {
                channel = LOGIN_CHANNEL;
                event = LOGIN_SUCCESS_EVENT;
            } else if (IdentityEventConstants.Event.AUTHENTICATION_STEP_FAILURE.equals(eventName)) {
                channel = LOGIN_CHANNEL;
                event = LOGIN_FAILURE_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_TERMINATE_V2.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_REVOKED_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_EXPIRE.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_EXPIRED_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_UPDATE.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_EXTEND.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_EXTENDED_EVENT;
            } else if (IdentityEventConstants.Event.SESSION_CREATE.equals(eventName)) {
                channel = SESSION_CHANNEL;
                event = SESSION_CREATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_UPDATE_USER_LIST_OF_ROLE.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_UPDATE_USER_LIST_OF_ROLE_EVENT;
            } else if (IdentityEventConstants.Event.POST_DELETE_USER.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_DELETE_USER_EVENT;
            } else if (IdentityEventConstants.Event.POST_UNLOCK_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_UNLOCK_ACCOUNT_EVENT;
            } else if (IdentityEventConstants.Event.POST_LOCK_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_LOCK_ACCOUNT_EVENT;
            } else if (IdentityEventConstants.Event.POST_USER_PROFILE_UPDATE.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_USER_PROFILE_UPDATED_EVENT;
            } else if (IdentityEventConstants.Event.POST_ENABLE_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_ACCOUNT_ENABLE_EVENT;
            } else if (IdentityEventConstants.Event.POST_DISABLE_ACCOUNT.equals(eventName)) {
                channel = USER_OPERATION_CHANNEL;
                event = POST_ACCOUNT_DISABLE_EVENT;
            } else if (isCredentialUpdateFlow(eventName)) {
                channel = CREDENTIAL_CHANGE_CHANNEL;
                event = POST_UPDATE_USER_CREDENTIAL;
            } else if (IdentityEventConstants.Event.POST_ADD_USER.equals(eventName)) {
                /*
                The user operation check must always precede the registration check, since user creation occurs before
                registration, and both events are triggered by the same event: POST_ADD_USER.
                // TODO this issue is due to sequence utility access of metadata.
                 */
                channel = USER_OPERATION_CHANNEL;
                event = POST_USER_CREATED_EVENT;
            }
        }
        return EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(WSO2.name())
                .build();
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

    public static Optional<UserClaim> generateUserClaim(String claimKey, String claimValue, String tenantDomain) {

        if (StringUtils.isBlank(claimKey) || StringUtils.isBlank(claimValue)) {
            return Optional.empty();
        }

        UserClaim.Builder userClaimBuilder = new UserClaim.Builder().uri(claimKey);

        String multiAttributeSeparator = FrameworkUtils.getMultiAttributeSeparator();
        if (multiAttributeSeparator == null) {
            multiAttributeSeparator = ","; // default fallback
        }

        if (isMultiValuedClaim(claimKey, tenantDomain)) {
            userClaimBuilder.value(StringUtils.isBlank(claimValue) ? new String[]{} :
                    claimValue.split(Pattern.quote(multiAttributeSeparator)));
        } else {
            userClaimBuilder.value(claimValue);
        }

        return Optional.of(userClaimBuilder.build());
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
            Optional<UserClaim> emailAddressUserClaimOptional =
                    generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress,
                            tenantDomain);
            emailAddressUserClaimOptional.ifPresent(user::addClaim);
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
            user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + user.getId());
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
                Optional<UserClaim> userClaimOptional = generateUserClaim(userClaimUri, userClaims.get(userClaimUri),
                        tenantDomain);
                userClaimOptional.ifPresent(userClaimList::add);
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
                user.setRef(constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + user.getId());
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

    private static boolean isBulkOperation() {

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        Flow.Name flowName = (flow != null) ? flow.getName() : null;

        return Flow.Name.BULK_RESOURCE_UPDATE.equals(flowName);
    }

    public static String constructFullURLWithEndpoint(String endpoint) {

        if (endpoint == null) {
            throw new IllegalArgumentException("Endpoint cannot be null.");
        }
        endpoint = constructBaseURL() + endpoint;
        return endpoint;
    }

    private static String constructBaseURL() {

        try {
            ServiceURLBuilder builder = ServiceURLBuilder.create();
            return builder.build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            log.debug("Error occurred while building the tenant qualified URL.", e);
        }
        return null;
    }
}
