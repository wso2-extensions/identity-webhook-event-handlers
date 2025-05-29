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
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerDataHolder;
import org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_INVALID_ORGANIZATION_ID;

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

            UserStoreManager userStoreManager = userRealm.getUserStoreManager();

            if (userStoreManager == null) {
                if (log.isDebugEnabled()) {
                    log.debug("UserStoreManager is null for tenant: " + tenantId);
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
}
