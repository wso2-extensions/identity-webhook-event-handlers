package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.RegistrationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

public class RegistrationEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(RegistrationEventHookHandler.class);
    private final EventConfigManager eventConfigManager;

    public RegistrationEventHookHandler(EventConfigManager eventConfigManager) {

        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.REGISTRATION_EVENT_HOOK_NAME;
    }

    @Override
    public boolean canHandle(MessageContext messageContext) throws IdentityRuntimeException {

        IdentityEventMessageContext identityContext = (IdentityEventMessageContext) messageContext;
        String eventName = identityContext.getEvent().getEventName();

        boolean canHandle = isSupportedEvent(eventName);
        if (canHandle) {
            log.debug(eventName + " event can be handled.");
        } else {
            log.debug(eventName + " event cannot be handled.");
        }
        return canHandle;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        RegistrationEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getRegistrationEventPayloadBuilder(EventSchema.WSO2);
        EventPublisherConfig registrationEventPublisherConfig;
        try {

            String tenantDomain =
                    String.valueOf(eventData.getEventParams().get(IdentityEventConstants.EventProperty.TENANT_DOMAIN));

            registrationEventPublisherConfig =
                    eventConfigManager.getEventPublisherConfigForTenant(tenantDomain, event.getEventName());

            EventPayload eventPayload;
            String eventUri;

            if ((IdentityEventConstants.Event.POST_ADD_USER.equals(event.getEventName()) ||
                    IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM.equals(event.getEventName()) ||
                    IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(event.getEventName())) &&
                    registrationEventPublisherConfig.isPublishEnabled()) {
                eventPayload = payloadBuilder.buildRegistrationSuccessEvent(eventData);
                eventUri =
                        eventConfigManager.getEventUri(
                                Constants.EventHandlerKey.WSO2.POST_REGISTRATION_SUCCESS_EVENT);
                SecurityEventTokenPayload securityEventTokenPayload = EventHookHandlerUtils
                        .buildSecurityEventToken(eventPayload, eventUri);
                EventHookHandlerUtils.publishEventPayload(securityEventTokenPayload, tenantDomain, eventUri);
            }
        } catch (IdentityEventException e) {
            log.debug("Error while retrieving event publisher configuration for tenant.", e);
        }
    }

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.Event.POST_ADD_USER.equals(eventName) ||
                IdentityEventConstants.Event.POST_SELF_SIGNUP_CONFIRM.equals(eventName) ||
                IdentityEventConstants.Event.POST_ADD_NEW_PASSWORD.equals(eventName);
    }

}
