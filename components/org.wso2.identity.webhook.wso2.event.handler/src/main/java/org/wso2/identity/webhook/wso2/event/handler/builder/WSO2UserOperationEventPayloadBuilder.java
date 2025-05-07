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

package org.wso2.identity.webhook.wso2.event.handler.builder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2UserGroupUpdateEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.common.Group;
import org.wso2.identity.webhook.wso2.event.handler.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.model.common.UserStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.carbon.user.core.constants.UserCoreClaimConstants.USER_ID_CLAIM_URI;
import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;

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

    private List<User> buildUserList(AbstractUserStoreManager userStoreManager, Map<String, Object> properties,
                                     String userListPropertyName)
            throws IdentityEventException {

        List<User> users = new ArrayList<>();

        String[] domainQualifiedUsernames = (String[]) properties.get(userListPropertyName);
        if (domainQualifiedUsernames != null && domainQualifiedUsernames.length > 0) {
            for (String domainQualifiedUsername : domainQualifiedUsernames) {
                User user = new User();
                String userId;
                try {
                    userId = userStoreManager.getUserClaimValue(domainQualifiedUsername, USER_ID_CLAIM_URI,
                            UserCoreConstants.DEFAULT_PROFILE);
                    user.setId(userId);

                    String emailAddress = userStoreManager.getUserClaimValue(domainQualifiedUsername,
                            FrameworkConstants.EMAIL_ADDRESS_CLAIM,
                            UserCoreConstants.DEFAULT_PROFILE);

                    UserClaim emailAddressUserClaim =
                            new UserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress);
                    List<UserClaim> userClaims = new ArrayList<>();
                    userClaims.add(emailAddressUserClaim);

                    user.setClaims(userClaims);
                } catch (UserStoreException e) {
                    throw new IdentityEventException("Error while extracting user claims for the user : " +
                            domainQualifiedUsername, e);
                }
                users.add(user);
            }
        }
        return users;
    }

    @Override
    public String getEventSchemaType() {

        return EVENT_SCHEMA_TYPE_WSO2;
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
