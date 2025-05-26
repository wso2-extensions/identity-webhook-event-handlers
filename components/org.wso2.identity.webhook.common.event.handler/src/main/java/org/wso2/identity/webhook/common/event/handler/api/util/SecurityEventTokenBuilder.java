package org.wso2.identity.webhook.common.event.handler.api.util;

import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;

/**
 * Security event token builder interface.
 */
public interface SecurityEventTokenBuilder {

    /**
     * Build a security event token payload.
     *
     * @param eventPayload   Event payload.
     * @param eventUri  Event URI.
     * @param eventData Event data.
     * @return Security event token payload.
     */
    SecurityEventTokenPayload buildSecurityEventTokenPayload(EventPayload eventPayload, String eventUri,
                                                             EventData eventData) throws IdentityEventException;

    /**
     * Get the event schema.
     *
     * @return Event schema.
     */
    EventSchema getEventSchema();
}
