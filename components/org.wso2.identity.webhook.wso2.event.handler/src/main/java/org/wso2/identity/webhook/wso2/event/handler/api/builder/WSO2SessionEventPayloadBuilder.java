package org.wso2.identity.webhook.wso2.event.handler.api.builder;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

public class WSO2SessionEventPayloadBuilder implements SessionEventPayloadBuilder {

    @Override
    public EventPayload buildSessionTerminateEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionCreateEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionUpdateEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionExpireEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventPayload buildSessionExtendEvent(EventData eventData) throws IdentityEventException {

        return null;
    }

    @Override
    public EventSchema getEventSchemaType() {

        return EventSchema.WSO2;
    }
}
