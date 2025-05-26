package org.wso2.identity.webhook.wso2.event.handler.api.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.util.SecurityEventTokenBuilder;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils.constructBaseURL;
import static org.wso2.identity.webhook.common.event.handler.api.util.EventPayloadUtils.getCorrelationID;

public class WSO2SecurityEventTokenBuilder implements SecurityEventTokenBuilder {

    @Override
    public SecurityEventTokenPayload buildSecurityEventTokenPayload(
            EventPayload eventPayload, String eventUri, EventData eventData) throws IdentityEventException {

        if (eventPayload == null) {
            throw new IdentityEventException("Invalid event payload input: Event payload input cannot be null.");
        }

        if (StringUtils.isEmpty(eventUri)) {
            throw new IdentityEventException("Invalid event URI input: Event URI input cannot be null or empty.");
        }

        Map<String, EventPayload> eventMap = new HashMap<>();
        eventMap.put(eventUri, eventPayload);

        // TODO : Add the audience and txn to the event payload.
        return new SecurityEventTokenPayload.WSO2Builder()
                .iss(constructBaseURL())
                .iat(System.currentTimeMillis())
                .jti(UUID.randomUUID().toString())
                .rci(getCorrelationID())
                .events(eventMap)
                .build();
    }

    @Override
    public EventSchema getEvenSchema() {

        return EventSchema.WSO2;
    }
}
