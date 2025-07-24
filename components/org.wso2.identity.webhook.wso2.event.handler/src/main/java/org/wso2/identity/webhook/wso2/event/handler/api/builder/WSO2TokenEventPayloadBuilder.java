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
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Map;

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

        Organization tenant = WSO2PayloadUtils.buildTenant(eventData);
        UserStore userStore = WSO2PayloadUtils.buildUserStore(eventData);
        Application application = buildApplication(eventData);
        AccessToken accessToken = buildAccessToken(eventData);
        User user = WSO2PayloadUtils.buildUser(eventData);

        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
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
