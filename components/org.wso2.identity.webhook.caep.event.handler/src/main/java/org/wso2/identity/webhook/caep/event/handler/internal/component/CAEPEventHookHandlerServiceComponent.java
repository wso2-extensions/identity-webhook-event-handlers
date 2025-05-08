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
@Component(name =
        "org.wso2.identity.webhook.caep.event.handler.internal.component.CAEPEventHookHandlerServiceComponent",
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
