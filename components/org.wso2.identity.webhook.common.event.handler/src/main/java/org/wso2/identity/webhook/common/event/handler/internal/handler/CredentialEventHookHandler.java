/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.common.event.handler.internal.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.model.EventPayload;
import org.wso2.identity.webhook.common.event.handler.api.builder.CredentialEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.constants.EventSchema;
import org.wso2.identity.webhook.common.event.handler.api.model.EventData;
import org.wso2.identity.webhook.common.event.handler.internal.config.EventPublisherConfig;
import org.wso2.identity.webhook.common.event.handler.internal.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerUtils;
import org.wso2.identity.webhook.common.event.handler.internal.util.PayloadBuilderFactory;

public class CredentialEventHookHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(CredentialEventHookHandler.class);
    private final EventConfigManager eventConfigManager;

    public CredentialEventHookHandler(EventConfigManager eventConfigManager) {

        this.eventConfigManager = eventConfigManager;
    }

    @Override
    public String getName() {

        return Constants.CREDENTIAL_EVENT_HOOK_NAME;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        EventData eventData = EventHookHandlerUtils.buildEventDataProvider(event);

        EventSchema schema = EventSchema.CAEP;
        CredentialEventPayloadBuilder payloadBuilder = PayloadBuilderFactory
                .getCredentialEventPayloadBuilder(schema);

        EventPublisherConfig credentialEventPublisherConfig;

        try {
            credentialEventPublisherConfig = EventHookHandlerUtils.getEventPublisherConfigForTenant(
                    (String) eventData.getSessionContext().getProperty("tenantDomain"),
                    event.getEventName(), eventConfigManager);

            EventPayload eventPayload = null;
            String eventUri = null;

        } catch (Exception e) {
            throw new IdentityEventException("Error occurred while building event payload", e);
        }
    }
}
