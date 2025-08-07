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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokenEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenIssuedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokedEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessToken;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Tenant;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Map;

/**
 * Builder class for creating WSO2 Token Event Payloads.
 */
public class WSO2TokenEventPayloadBuilder implements TokenEventPayloadBuilder {

    @Override
    public Constants.EventSchema getEventSchemaType() {

        return Constants.EventSchema.WSO2;
    }

    @Override
    public EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException {

        //TODO: Implement the logic to build the WSO2TokenRevokedEventPayload from eventData.

        return new WSO2TokenRevokedEventPayload.Builder()
                .accessTokens(null)
                .initiatorType(null)
                .tenant(null)
                .userStore(null)
                .user(null)
                .application(null)
                .build();
    }

    @Override
    public EventPayload buildAccessTokenIssueEvent(EventData eventData) throws IdentityEventException {

        Tenant tenant = WSO2PayloadUtils.buildTenant();
        UserStore userStore = WSO2PayloadUtils.buildUserStore(eventData);
        Application application = buildApplication(eventData);
        AccessToken accessToken = buildAccessToken(eventData);
        Organization organization = WSO2PayloadUtils.buildOrganizationFromIdentityContext(
                IdentityContext.getThreadLocalIdentityContext());
        User user = WSO2PayloadUtils.buildUser(eventData);
        user.setOrganization(organization);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getCurrentFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = flow.getName().name();
        }

        return new WSO2TokenIssuedEventPayload.Builder()
                .initiatorType(initiatorType)
                .accessToken(accessToken)
                .application(application)
                .user(user)
                .tenant(tenant)
                .organization(organization)
                .userStore(userStore)
                .action(action)
                .build();
    }

    private AccessToken buildAccessToken(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        String iat = String.valueOf(properties.get(IdentityEventConstants.EventProperty.IAT));
        String tokenType = (String) properties.get(IdentityEventConstants.EventProperty.TOKEN_TYPE);
        String grantType = (String) properties.get(IdentityEventConstants.EventProperty.GRANT_TYPE);
        String jti = (String) properties.get(IdentityEventConstants.EventProperty.JTI);

        if (StringUtils.isNotBlank(iat) && StringUtils.isNotBlank(tokenType)) {
            return new AccessToken.Builder()
                    .tokenType(tokenType)
                    .grantType(grantType)
                    .iat(iat)
                    .jti(jti)
                    .build();
        }
        return null;
    }

    private Application buildApplication(EventData eventData) {

        if (eventData == null) {
            return null;
        }
        Map<String, Object> properties = eventData.getProperties();

        String applicationId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID));
        String applicationName = (String) properties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME);
        String consumerKey = (String) properties.get(IdentityEventConstants.EventProperty.CONSUMER_KEY);

        if (StringUtils.isNotBlank(applicationId)) {
            return new Application.Builder()
                    .id(applicationId)
                    .name(applicationName)
                    .consumerKey(consumerKey)
                    .build();
        }
        return null;
    }
}
