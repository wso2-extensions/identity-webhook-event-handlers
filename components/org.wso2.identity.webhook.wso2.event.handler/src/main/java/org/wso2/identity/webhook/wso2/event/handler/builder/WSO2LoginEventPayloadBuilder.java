/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.wso2.event.handler.builder;

import org.wso2.identity.webhook.common.event.handler.model.AuthStep;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.constant.Constants;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2AuthenticationFailedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2AuthenticationSuccessEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.WSO2BaseEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.model.common.UserClaim;
import org.wso2.identity.webhook.wso2.event.handler.model.common.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.data.publisher.authentication.analytics.login.model.AuthenticationData;
import org.wso2.identity.event.publishers.common.model.EventPayload;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.wso2.identity.webhook.common.event.handler.constant.Constants.EVENT_SCHEMA_TYPE_WSO2;
import static org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils.getReference;

/**
 * WSO2 Login Event Payload Builder.
 */
public class WSO2LoginEventPayloadBuilder implements LoginEventPayloadBuilder {

    @Override
    public EventPayload buildAuthenticationSuccessEvent(EventData eventData) {

        WSO2AuthenticationSuccessEventPayload payload = new WSO2AuthenticationSuccessEventPayload();
        buildEventPayload(eventData, payload);
        return payload;
    }

    @Override
    public EventPayload buildAuthenticationFailedEvent(EventData eventData) {

        WSO2AuthenticationFailedEventPayload payload = new WSO2AuthenticationFailedEventPayload();
        buildEventPayload(eventData, payload);
        return payload;
    }

    @Override
    public String getEventSchemaType() {

        return EVENT_SCHEMA_TYPE_WSO2;
    }

    private void buildEventPayload(EventData eventData, WSO2BaseEventPayload payload) {

        User user = new User();
        AuthenticationData<?, ?> authenticationData = eventData.getAuthenticationData();
        AuthenticatedUser authenticatedUser = eventData.getAuthenticatedUser();
        AuthenticationContext authenticationContext = eventData.getAuthenticationContext();

        populateUserAttributes(authenticatedUser, user);

        user.setId(authenticationData.getUserId());
        user.setRef(getReference(authenticationContext.getTenantDomain(),
                Constants.SCIM2_ENDPOINT, authenticationData.getUserId()));
        payload.setUser(user);
        payload.setOrganization(new Organization(IdentityTenantUtil.getTenantId(authenticationContext.getTenantDomain()),
                authenticationContext.getTenantDomain()));
        payload.setUserStore(new UserStore(authenticationData.getUserStoreDomain()));
        payload.setApplication(new Application(authenticationContext.getServiceProviderResourceId(),
                authenticationData.getServiceProvider()));

        if (payload instanceof WSO2AuthenticationSuccessEventPayload) {
            List<AuthStep> authSteps = eventData.getAuthSteps();
            for (AuthStep authStep : authSteps) {
                ((WSO2AuthenticationSuccessEventPayload) payload).addAuthenticationMethod(authStep.getIdp());
            }
        }
    }

    private void populateUserAttributes(AuthenticatedUser authenticatedUser, User user) {
        
        List<UserClaim> userClaims = new ArrayList<>();
        if (authenticatedUser == null) {
            return;
        }
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
                    default:
                        userClaims.add(new UserClaim(claimUri, claimValue));
                        break;
                }
            }
        }
        user.setClaims(userClaims);
    }
}
