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
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2RegistrationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.FIRST_NAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.LAST_NAME_CLAIM_URI;
import static org.wso2.identity.webhook.wso2.event.handler.internal.constant.Constants.SCIM2_USERS_ENDPOINT;

public class WSO2RegistrationEventPayloadBuilder implements RegistrationEventPayloadBuilder {

    @Override
    public EventPayload buildRegistrationSuccessEvent(EventData eventData) throws IdentityEventException {

        Map<String, Object> properties = eventData.getEventParams();
        String tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        String tenantDomain = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

        AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) properties.get(USER_STORE_MANAGER);
        String userStoreDomainName = userStoreManager.getRealmConfiguration()
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

        UserStore userStore = new UserStore(userStoreDomainName);

        User newUser = new User();
        enrichUser(properties, newUser);
        addRoles(properties, newUser);

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = flow.getName().name();
        }

        List<String> credentialEnrolled = new ArrayList<>();
        credentialEnrolled.add("PASSWORD");//TODO check totp and passkey flows later.

        return new WSO2RegistrationSuccessEventPayload.Builder()
                .initiatorType(initiatorType)
                .action(action)
                .user(newUser)
                .tenant(organization)
                .userStore(userStore)
                .credentialsEnrolled(credentialEnrolled)
                .build();
    }

    private void enrichUser(Map<String, Object> properties, User user) {

        if (properties.containsKey(IdentityEventConstants.EventProperty.USER_CLAIMS)) {
            Map<String, String> claims = (Map<String, String>) properties.get(IdentityEventConstants.EventProperty
                    .USER_CLAIMS);

            String userId = claims.get(FrameworkConstants.USER_ID_CLAIM);
            user.setId(userId);
            user.setRef(
                    EventPayloadUtils.constructFullURLWithEndpoint(SCIM2_USERS_ENDPOINT) + "/" + user.getId());

            List<UserClaim> userClaims = new ArrayList<>();
            String emailAddress = claims.get(FrameworkConstants.EMAIL_ADDRESS_CLAIM);
            String givenName = claims.get(FIRST_NAME_CLAIM_URI);
            String lastName = claims.get(LAST_NAME_CLAIM_URI);

            UserClaim emailAddressUserClaim = new UserClaim(FrameworkConstants.EMAIL_ADDRESS_CLAIM, emailAddress);
            UserClaim givenNameUserClaim = new UserClaim(FIRST_NAME_CLAIM_URI, givenName);
            UserClaim lastNameUserClaim = new UserClaim(LAST_NAME_CLAIM_URI, lastName);

            userClaims.add(emailAddressUserClaim);
            userClaims.add(givenNameUserClaim);
            userClaims.add(lastNameUserClaim);
            user.setClaims(userClaims);
        }
    }

    private void addRoles(Map<String, Object> properties, User user) {

        if (!properties.containsKey(IdentityEventConstants.EventProperty.ROLE_LIST)) {
            return;
        }
        String[] roleList = (String[]) properties.get(IdentityEventConstants.EventProperty.ROLE_LIST);

        for (String role : roleList) {
            user.addRole(role);
        }
    }

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }
}
