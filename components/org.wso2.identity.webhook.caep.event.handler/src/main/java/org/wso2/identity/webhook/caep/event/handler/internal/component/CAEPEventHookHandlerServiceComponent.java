package org.wso2.identity.webhook.caep.event.handler.internal.component;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.identity.webhook.caep.event.handler.api.builder.CAEPSessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;

/**
 * CAEP Event Handler Service Component.
 */
@Component(
        name = "org.wso2.identity.webhook.caep.event.handler.internal.component.CAEPEventHookHandlerServiceComponent",
        immediate = true)
public class CAEPEventHookHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(CAEPEventHookHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            log.debug("WSO2 CAEP Event Handler is activated.");

            context.getBundleContext().registerService(SessionEventPayloadBuilder.class.getName(),
                    new CAEPSessionEventPayloadBuilder(), null);

        } catch (Exception e) {
            log.error("Error while activating CAEP event handler.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("WSO2 CAEP Event Handler is deactivated.");
    }

}
