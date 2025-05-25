package org.wso2.identity.webhook.common.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

public interface RegistrationEventPayloadBuilder {

    EventPayload buildRegistrationSuccessEvent(EventData eventData) throws IdentityEventException;

    /**
     * Get the event schema type.
     *
     * @return Event schema type.
     */
    EventSchema getEventSchemaType();

}
