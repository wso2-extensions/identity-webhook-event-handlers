package org.wso2.identity.webhook.common.event.handler.internal.util;

import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.util.SecurityEventTokenBuilder;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;

import java.util.List;

public class SecurityEventTokenBuilderFactory {

    public static SecurityEventTokenBuilder getSecurityEventTokenBuilder(EventSchema eventSchema) {

       List<SecurityEventTokenBuilder> securityEventTokenBuilders =
                EventHookHandlerDataHolder.getInstance().getSecurityEventTokenBuilders();
        for (SecurityEventTokenBuilder securityEventTokenBuilder : securityEventTokenBuilders) {
            if (securityEventTokenBuilder.getEventSchema().equals(eventSchema)) {
                return securityEventTokenBuilder;
            }
        }
        return null;
    }
}
