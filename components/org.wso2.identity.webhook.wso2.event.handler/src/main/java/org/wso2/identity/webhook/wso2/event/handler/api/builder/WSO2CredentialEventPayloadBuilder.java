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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserCredentialUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;

public class WSO2CredentialEventPayloadBuilder implements CredentialEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2CredentialEventPayloadBuilder.class);

    @Override
    public EventPayload buildCredentialUpdateEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));
        String tenantId = String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain));
        String userName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_NAME));
        String userStoreDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN));

        UserStoreManager userStoreManager = WSO2PayloadUtils.getUserStoreManagerByTenantDomain(tenantDomain);
        User user = buildUser(userStoreManager, userStoreDomain, userName, tenantDomain);

        Organization organization = new Organization(tenantId, tenantDomain);
        UserStore userStore = new UserStore(userStoreDomain);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String action = null;
        String initiatorType = null;

        if (flow != null) {
            action = Optional.ofNullable(getAction(flow.getName()))
                    .map(Enum::name)
                    .orElse(null);
            initiatorType = flow.getInitiatingPersona().name();
        }
        return new WSO2UserCredentialUpdateEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .credentialType("PASSWORD")
                .user(user)
                .tenant(organization)
                .userStore(userStore)
                .build();
    }

    private User buildUser(UserStoreManager userStoreManager, String userStoreDomain, String userName,
                           String tenantDomain)
            throws IdentityEventException {

        User user = new User();
        if (userStoreManager != null) {
            String domainQualifiedUserName = userStoreDomain + "/" + userName;
            enrichUser(userStoreManager, domainQualifiedUserName, user, tenantDomain);
            user.setRef(EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + user.getId());
        }
        return user;
    }

    private static void enrichUser(UserStoreManager userStoreManager, String domainQualifiedUserName, User user,
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
                    WSO2PayloadUtils.generateUserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress,
                            tenantDomain);
            List<UserClaim> userClaims = new ArrayList<>();
            userClaims.add(emailAddressUserClaim);

            user.setClaims(userClaims);

        } catch (UserStoreException e) {
            throw new IdentityEventException(
                    "Error while extracting user claims for the user : " + domainQualifiedUserName, e);
        }
    }

    private PasswordUpdateAction getAction(Flow.Name name) {

        if (name == null) {
            return null;
        }

        switch (name) {
            case PROFILE_UPDATE:
                return PasswordUpdateAction.UPDATE;
            case PASSWORD_RESET:
                return PasswordUpdateAction.RESET;
            case USER_REGISTRATION_INVITE_WITH_PASSWORD:
                return PasswordUpdateAction.INVITE;
            default: {
                log.warn(name + " is not a valid password update action.");
                return null;
            }
        }
    }

    public enum PasswordUpdateAction {
        UPDATE, RESET, INVITE
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }
}
