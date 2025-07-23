package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.Flow;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokensEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenIssueEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokeEventPayload;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessToken;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;
import org.wso2.identity.webhook.wso2.event.handler.internal.util.WSO2PayloadUtils;

import java.util.Map;

public class WSO2TokensEventPayloadBuilder implements TokensEventPayloadBuilder {

    @Override
    public org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema getEventSchemaType() {

        return org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.WSO2;
    }

    @Override
    public EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException {

        //TODO: Implement the logic to build the WSO2TokenRevokeEventPayload from eventData.

        return new WSO2TokenRevokeEventPayload.Builder()
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

        Map<String, Object> properties = eventData.getEventParams();
        String tenantDomain = eventData.getTenantDomain();

        String userStoreDomainName = WSO2PayloadUtils.resolveUserStoreDomain(properties);
        UserStore userStore = new UserStore(userStoreDomainName);

        User user = new User();
        user.setId(eventData.getUserId());

        WSO2PayloadUtils.enrichMandatoryUserClaims(eventData, tenantDomain, user);

        String tenantId = null;
        if (properties.get(IdentityEventConstants.EventProperty.TENANT_ID) != null) {
            tenantId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.TENANT_ID));
        } else {
            RealmConfiguration realmConfiguration = WSO2PayloadUtils.getRealmConfigurationByTenantDomain(tenantDomain);
            if (realmConfiguration != null)
                tenantId = String.valueOf(realmConfiguration.getTenantId());
        }

        String applicationId = String.valueOf(properties.get(IdentityEventConstants.EventProperty.APPLICATION_ID));
        String applicationName = (String) properties.get(IdentityEventConstants.EventProperty.APPLICATION_NAME);
        String consumerKey = (String) properties.get("CONSUMER_KEY");

        Application application = null;
        if (StringUtils.isNotBlank(applicationId)) {
            application = new Application(applicationId, applicationName);
            application.setConsumerKey(consumerKey);
        }

        String iat = String.valueOf(properties.get("IAT"));
        String tokenType = (String) properties.get("TOKEN_TYPE");
        String grantType = (String) properties.get("GRANT_TYPE");

        AccessToken accessToken = null;
        if (StringUtils.isNotBlank(iat) && StringUtils.isNotBlank(tokenType)) {
            accessToken = new AccessToken(iat, tokenType);
            accessToken.setGrantType(grantType);
        }

        Organization organization = new Organization(tenantId, tenantDomain);
        Flow flow = IdentityContext.getThreadLocalIdentityContext().getFlow();
        String initiatorType = null;
        String action = null;
        if (flow != null) {
            initiatorType = flow.getInitiatingPersona().name();
            action = flow.getName().name();
        }

        return new WSO2TokenIssueEventPayload.Builder()
                .initiatorType(initiatorType)
                .accessToken(accessToken)
                .application(application)
                .user(user)
                .tenant(organization)
                .userStore(userStore)
                .action(action)
                .build();
    }

}
