package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokensEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.WSO2TokenRevokeEventPayload;

public class WSO2TokensEventPayloadBuilder implements TokensEventPayloadBuilder {

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.WSO2;
    }

    @Override
    public EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException {

        //TODO: Implement the logic to build the WSO2TokenRevokeEventPayload from eventData.

        return new WSO2TokenRevokeEventPayload.Builder()
                .accessTokenId(null)
                .initiatorType(null)
                .tenant(null)
                .userStore(null)
                .user(null)
                .application(null)
                .build();
    }
}
