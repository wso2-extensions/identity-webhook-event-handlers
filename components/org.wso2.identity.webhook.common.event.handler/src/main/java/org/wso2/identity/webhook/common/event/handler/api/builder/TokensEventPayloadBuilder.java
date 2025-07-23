package org.wso2.identity.webhook.common.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

public interface TokensEventPayloadBuilder {

    /**
     * Get the event schema type.
     *
     * @return Event schema type.
     */
    Constants.EventSchema getEventSchemaType();

    EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException;

    EventPayload buildAccessTokenIssueEvent(EventData eventData) throws IdentityEventException;

}
