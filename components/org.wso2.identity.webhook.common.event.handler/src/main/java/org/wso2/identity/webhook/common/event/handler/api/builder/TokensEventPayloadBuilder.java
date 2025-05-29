package org.wso2.identity.webhook.common.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

public interface TokensEventPayloadBuilder {

    /**
     * Returns the EventSchema type of the event payload.
     *
     * @return Event Schema.
     */
    EventSchema getEventSchemaType();

    EventPayload buildAccessTokenRevokeEvent(EventData eventData) throws IdentityEventException;

}
