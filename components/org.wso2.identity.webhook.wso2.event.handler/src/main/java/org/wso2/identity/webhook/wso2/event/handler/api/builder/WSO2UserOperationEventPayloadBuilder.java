/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserAccountEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2UserGroupUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Group;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.PRE_DELETE_USER_USER_ID_FOR_WEB_SUB_HUB;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_ENDPOINT;

/**
 * WSO2 UserOperation Event Payload Builder.
 */
public class WSO2UserOperationEventPayloadBuilder implements UserOperationEventPayloadBuilder {

    private static final Log log = LogFactory.getLog(WSO2UserOperationEventPayloadBuilder.class);

    @Override
    public EventPayload buildUserGroupUpdateEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration().getUserStoreProperty
                (UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        Group group = buildGroup(properties, userStoreManager);
        UserStore userStore = new UserStore(userStoreDomainName);

        Organization organization = new Organization(tenantId, tenantDomain);
        String initiatorType = String.valueOf(properties.get(IdentityEventConstants.EventProperty.INITIATOR_TYPE));

        return new WSO2UserGroupUpdateEventPayload.Builder()
                .initiatorType(initiatorType)
                .group(group)
                .organization(organization)
                .userStore(userStore)
                .build();
    }

    @Override
    public EventPayload buildUserDeleteEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration().getUserStoreProperty
                (UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        String userName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_NAME));
        String userId =
                String.valueOf(IdentityUtil.threadLocalProperties.get().get(PRE_DELETE_USER_USER_ID_FOR_WEB_SUB_HUB));

        String emailAddress;
        try {
            emailAddress = userStoreManager.getUserClaimValue(userName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error while extracting user claims for the user : " + userName, e);
        }

        UserClaim emailAddressUserClaim = new UserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress);
        List<UserClaim> userClaims = new ArrayList<>();
        userClaims.add(emailAddressUserClaim);

        User deletedUser = new User();
        deletedUser.setId(userId);
        deletedUser.setRef(EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_ENDPOINT) + "/" + userId);
        deletedUser.setClaims(userClaims);

        Organization organization = new Organization(tenantId, tenantDomain);
        String initiatorType = String.valueOf(properties.get(IdentityEventConstants.EventProperty.INITIATOR_TYPE));

        return new WSO2UserAccountEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(deletedUser)
                .organization(organization)
                .userStore(userStore)
                .build();
    }

    @Override
    public EventPayload buildUserUnlockAccountEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration().getUserStoreProperty
                (UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        String userName =
                String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.USER_NAME));

        User unlockedUser = new User();
        enrichUser(userStoreManager, userName, unlockedUser);
        unlockedUser.setRef(
                EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_ENDPOINT) + "/" + unlockedUser.getId());

        Organization organization = new Organization(tenantId, tenantDomain);
        String initiatorType = String.valueOf(properties.get(IdentityEventConstants.EventProperty.INITIATOR_TYPE));

        return new WSO2UserAccountEventPayload.Builder()
                .initiatorType(initiatorType)
                .user(unlockedUser)
                .organization(organization)
                .userStore(userStore)
                .build();
    }

    private List<User> buildUserList(AbstractUserStoreManager userStoreManager, Map<String, Object> properties,
                                     String userListPropertyName)
            throws IdentityEventException {

        List<User> users = new ArrayList<>();

        String[] domainQualifiedUsernames = (String[]) properties.get(userListPropertyName);
        if (domainQualifiedUsernames != null) {
            for (String domainQualifiedUsername : domainQualifiedUsernames) {
                User user = new User();
                enrichUser(userStoreManager, domainQualifiedUsername, user);
                users.add(user);
            }
        }
        return users;
    }

    private static void enrichUser(AbstractUserStoreManager userStoreManager, String userName, User user)
            throws IdentityEventException {

        String userId;
        try {
            userId = userStoreManager.getUserClaimValue(userName, FrameworkConstants.USER_ID_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
            user.setId(userId);

            String emailAddress = userStoreManager.getUserClaimValue(userName, FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                    UserCoreConstants.DEFAULT_PROFILE);
            UserClaim emailAddressUserClaim = new UserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress);
            List<UserClaim> userClaims = new ArrayList<>();
            userClaims.add(emailAddressUserClaim);

            user.setClaims(userClaims);

        } catch (UserStoreException e) {
            throw new IdentityEventException("Error while extracting user claims for the user : " + userName, e);
        }
    }

    @Override
    public String getEventSchemaType() {

        return EventSchema.WSO2.name();
    }

    private Group buildGroup(Map<String, Object> properties, AbstractUserStoreManager userStoreManager)
            throws IdentityEventException {

        String groupName = String.valueOf(properties.get(IdentityEventConstants.EventProperty.ROLE_NAME));
        org.wso2.carbon.user.core.common.Group groupFromUserStore;
        try {
            groupFromUserStore = userStoreManager.getGroupByGroupName(groupName, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            throw new IdentityEventException("Error while extracting group Id for the group Name: " + groupName, e);
        }
        String groupId = groupFromUserStore.getGroupID();
        String groupLocation = groupFromUserStore.getLocation();

        List<User> deletedUsers =
                buildUserList(userStoreManager, properties, IdentityEventConstants.EventProperty.DELETED_USERS);
        List<User> addedUsers =
                buildUserList(userStoreManager, properties, IdentityEventConstants.EventProperty.NEW_USERS);

        Group group = new Group();
        group.setName(groupName);
        group.setRef(groupLocation);
        group.setId(groupId);
        group.setRemovedUsers(deletedUsers);
        group.setAddedUsers(addedUsers);

        return group;
    }
}
