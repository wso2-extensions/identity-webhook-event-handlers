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
import org.wso2.carbon.identity.event.publisher.api.model.EventContext;
import org.wso2.carbon.identity.event.publisher.api.model.EventPayload;
import org.wso2.carbon.identity.event.publisher.api.model.SecurityEventTokenPayload;
import org.wso2.carbon.identity.webhook.metadata.api.model.Channel;
import org.wso2.carbon.identity.webhook.metadata.api.model.EventProfile;
import org.wso2.identity.webhook.common.event.handler.api.builder.TokensEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;
import org.wso2.identity.webhook.common.event.handler.internal.component.EventHookHandlerDataHolder;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

import java.util.List;
import java.util.Objects;

import static org.wso2.identity.webhook.common.event.handler.internal.constant.Constants.EVENT_PROFILE_VERSION;

public class TokensEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(TokensEventHookHandler.class);

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        try {
            List<EventProfile> eventProfileList =
                    EventHookHandlerDataHolder.getInstance().getWebhookMetadataService().getSupportedEventProfiles();

            if (eventProfileList.isEmpty()) {
                log.warn("No event profiles found in the webhook metadata service. " +
                        "Skipping registration event handling.");
                return;
            }
            for (EventProfile eventProfile : eventProfileList) {

                //TODO: Add the implementation to read the Event Schema Type from the Tenant Configuration
                org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema
                        schema =
                        org.wso2.identity.webhook.common.event.handler.api.constants.Constants.EventSchema.valueOf(
                                eventProfile.getProfile());

                EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

                TokensEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                        .getTokensEventPayloadBuilder(schema);

                if (payloadBuilder == null) {
                    log.debug("Skipping registration event handling for event " +
                            eventProfile.getProfile());
                    continue;
                }
                EventMetadata eventMetadata =
                        EventHookHandlerUtils.getEventProfileManagerByProfile(eventProfile.getProfile(),
                                event.getEventName());
                if (eventMetadata == null) {
                    log.debug("No event metadata found for event: " + event.getEventName() +
                            " in profile: " + eventProfile.getProfile());
                    continue;
                }
                String tenantDomain = eventData.getTenantDomain();

                EventPayload eventPayload;
                String eventUri;

                List<Channel> channels = eventProfile.getChannels();
                Channel tokensChannel = channels.stream()
                        .filter(channel -> eventMetadata.getChannel().equals(channel.getUri()))
                        .findFirst()
                        .orElse(null);
                if (tokensChannel == null) {
                    log.debug("No channel found for tokens event profile: " + eventProfile.getProfile());
                    continue;
                }

                eventUri = tokensChannel.getEvents().stream()
                        .filter(channelEvent -> Objects.equals(eventMetadata.getEvent(),
                                channelEvent.getEventUri()))
                        .findFirst()
                        .map(org.wso2.carbon.identity.webhook.metadata.api.model.Event::getEventUri)
                        .orElse(null);

                EventContext eventContext = EventContext.builder()
                        .tenantDomain(tenantDomain)
                        .eventUri(tokensChannel.getUri())
                        .eventProfileName(eventProfile.getProfile())
                        .eventProfileVersion(EVENT_PROFILE_VERSION)
                        .build();

                boolean publisherCanHandleEvent = EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                        .canHandleEvent(eventContext);

                if ((IdentityEventConstants.Event.TOKEN_REVOKED.equals(event.getEventName())) && publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildAccessTokenRevokeEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload =
                            EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);
                } else if (IdentityEventConstants.Event.TOKEN_ISSUED.equals(event.getEventName()) && publisherCanHandleEvent) {
                    eventPayload = payloadBuilder.buildAccessTokenIssueEvent(eventData);
                    SecurityEventTokenPayload securityEventTokenPayload =
                            EventHookHandlerUtils.buildSecurityEventToken(eventPayload, eventUri);
                    EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                            .publish(securityEventTokenPayload, eventContext);
                }
            }
        } catch (Exception e) {
            log.warn("Error while retrieving token event publisher configuration for tenant.", e);
        }
    }

    @Override
    public String getName() {

        return Constants.TOKENS_EVENT_HOOK_NAME;
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

    private boolean isSupportedEvent(String eventName) {

        return IdentityEventConstants.Event.TOKEN_REVOKED.equals(eventName) ||
               IdentityEventConstants.Event.TOKEN_ISSUED.equals(eventName);
    }
}
