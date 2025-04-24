package org.wso2.identity.webhook.common.event.handler.internal.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.identity.event.common.publisher.model.EventContext;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.event.common.publisher.model.SecurityEventTokenPayload;
import org.wso2.identity.webhook.common.event.handler.api.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.service.EventHookHandlerDataHolder;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils.CORRELATION_ID_MDC;

public class EventHookHandlerInternalUtils {

    private static final Log log = LogFactory.getLog(EventHookHandlerInternalUtils.class);
    private static volatile EventHookHandlerInternalUtils instance;

    private EventHookHandlerInternalUtils() {}

    public static EventHookHandlerInternalUtils getInstance() {

        if (instance == null) {
            synchronized (EventHookHandlerInternalUtils.class) {
                if (instance == null) {
                    instance = new EventHookHandlerInternalUtils();
                }
            }
        }
        return instance;
    }

    /**
     * Build the event data provider.
     *
     * @param event Event object.
     * @return Event data object.
     */
    public EventData buildEventDataProvider(Event event) throws IdentityEventException {

        Map<String, Object> properties = event.getEventProperties();
        if (properties == null) {
            throw new IdentityEventException("Properties cannot be null");
        }

        Map<String, Object> params = properties.containsKey("params") ?
                (Map<String, Object>) properties.get("params") : null;
        AuthenticationContext context = properties.containsKey("context") ?
                (AuthenticationContext) properties.get("context") : null;
        AuthenticatorStatus status = properties.containsKey("authenticationStatus") ?
                (AuthenticatorStatus) properties.get("authenticationStatus") : null;
        HttpServletRequest request = params != null ? (HttpServletRequest) params.get("request") : null;

        AuthenticatedUser authenticatedUser = null;
        if (params != null) {
            Object user = params.get("user");
            if (user instanceof AuthenticatedUser) {
                authenticatedUser = (AuthenticatedUser) user;
                if (context != null) {
                    setLocalUserClaimsToAuthenticatedUser(authenticatedUser, context);
                }
            }
        }

        return EventData.builder()
                .eventName(event.getEventName())
                .request(request)
                .eventParams(params)
                .authenticationContext(context)
                .authenticatorStatus(status)
                .authenticatedUser(authenticatedUser)
                .build();
    }


    /**
     * Retrieve the audience.
     *
     * @param eventUri     Event URI.
     * @return Audience string.
     */
    public SecurityEventTokenPayload buildSecurityEventToken(EventPayload eventPayload, String eventUri)
            throws IdentityEventException {

        if (eventPayload == null) {
            throw new IdentityEventException("Invalid event payload input: Event payload input cannot be null.");
        }

        if (StringUtils.isEmpty(eventUri)) {
            throw new IdentityEventException("Invalid event URI input: Event URI input cannot be null or empty.");
        }

        Map<String, EventPayload> eventMap = new HashMap<>();
        eventMap.put(eventUri, eventPayload);

        return SecurityEventTokenPayload.builder()
                .iss(constructBaseURL())
                .iat(System.currentTimeMillis())
                .jti(UUID.randomUUID().toString())
                .rci(getCorrelationID())
                .events(eventMap)
                .build();
    }

    /**
     * Get correlation id from the MDC.
     * If not then generate a random UUID, add it to MDC and return the UUID.
     *
     * @return Correlation id
     */
    public String getCorrelationID() {

        String correlationID = MDC.get(CORRELATION_ID_MDC);
        if (StringUtils.isBlank(correlationID)) {
            correlationID = UUID.randomUUID().toString();
            MDC.put(CORRELATION_ID_MDC, correlationID);
        }
        return correlationID;
    }





    private void setLocalUserClaimsToAuthenticatedUser(AuthenticatedUser authenticatedUser,
                                                       AuthenticationContext context) {

        Map<String, String> claimMappings = (Map<String, String>) context.getParameters()
                .get(Constants.SP_TO_CARBON_CLAIM_MAPPING);

        if (claimMappings == null) {
            log.debug("No local claim mappings found for the authenticated user from the context.");
            return;
        }

        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();

        if (userAttributes == null) {
            userAttributes = new HashMap<>();
        }

        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {

            ClaimMapping claimMapping = entry.getKey();
            Claim localClaim = claimMapping.getLocalClaim();

            if (claimMappings.containsKey(localClaim.getClaimUri())) {
                localClaim.setClaimUri(claimMappings.get(localClaim.getClaimUri()));
            }
        }
    }

    /**
     * Get the tenant qualified URL.
     *
     * @return Tenant qualified URL.
     */
    public String constructBaseURL() {

        try {
            ServiceURLBuilder builder = ServiceURLBuilder.create();
            return builder.build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            log.debug("Error occurred while building the tenant qualified URL.", e);
        }
        return null;
    }


    /**
     * Publish the event payload.
     *
     * @param securityEventTokenPayload Security event token payload.
     * @param tenantDomain              Tenant domain.
     * @param eventUri                  Event URI.
     * @throws IdentityEventException If an error occurs.
     */
    public void publishEventPayload(SecurityEventTokenPayload securityEventTokenPayload, String tenantDomain,
                                    String eventUri) throws IdentityEventException {

        try {
            EventContext eventContext = EventContext.builder()
                    .tenantDomain(tenantDomain)
                    .eventUri(eventUri)
                    .build();
            EventHookHandlerDataHolder.getInstance().getEventPublisherService()
                    .publish(securityEventTokenPayload, eventContext);
        } catch (Exception e) {
            throw new IdentityEventException(String.format("Error while handling %s event.",
                    eventUri), e);
        }
    }

}
