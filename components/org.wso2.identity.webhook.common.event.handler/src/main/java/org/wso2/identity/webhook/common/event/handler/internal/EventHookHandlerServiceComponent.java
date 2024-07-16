/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.internal;

import org.wso2.identity.webhook.common.event.handler.LoginEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import com.wso2.identity.asgardeo.event.configuration.mgt.core.service.EventConfigurationMgtService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.EventPublisherService;

/**
 * WSO2 Event Handler service component class.
 */
@Component(
        name = "org.wso2.identity.webhook.common.event.handler.internal.EventHookHandlerServiceComponent",
        immediate = true)
public class EventHookHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(EventHookHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            log.debug("Event Handler is activated.");
            BundleContext bundleContext = context.getBundleContext();
            LoginEventHookHandler loginEventHookHandler = new LoginEventHookHandler();
            if (loginEventHookHandler.isLoginEventHandlerEnabled()) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        loginEventHookHandler, null);
            }
        } catch (Exception e) {
            log.error("Error while activating event handler.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("Event Handler is deactivated.");
    }

    @Reference(
            name = "login.event.payload.builder",
            service = LoginEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeLoginEventPayloadBuilder"
    )
    protected void addLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        log.debug("Adding the Login Event Payload Builder Service : " +
                    loginEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addLoginEventPayloadBuilder(loginEventPayloadBuilder);
    }

    protected void removeLoginEventPayloadBuilder(LoginEventPayloadBuilder loginEventPayloadBuilder) {

        log.debug("Removing the Login Event Payload Builder Service : " +
                    loginEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().removeLoginEventPayloadBuilder(loginEventPayloadBuilder);
    }

    @Reference(
            name = "resource.configuration.manager",
            service = ConfigurationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterConfigurationManager"
    )
    protected void registerConfigurationManager(ConfigurationManager configurationManager) {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(configurationManager);
    }

    protected void unregisterConfigurationManager(ConfigurationManager configurationManager) {

        EventHookHandlerDataHolder.getInstance().setConfigurationManager(null);
    }

    @Reference(
            name = "event.configuration.manager.service",
            service = EventConfigurationMgtService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterEventConfigurationManager"
    )
    protected void registerEventConfigurationManager(EventConfigurationMgtService eventConfigurationMgtService) {
        /* Reference EventConfigurationMgtService to guarantee that this component will wait until
        event configuration core is started */
    }

    protected void unregisterEventConfigurationManager(EventConfigurationMgtService eventConfigurationMgtService) {
        /* Reference EventConfigurationMgtService to guarantee that this component will wait until
        event configuration core is started */
    }

    @Reference(
            name = "org.wso2.identity.event.common.publisher",
            service = EventPublisherService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetEventPublisherService"
    )
    protected void setEventPublisherService(EventPublisherService eventPublisherService) {

        EventHookHandlerDataHolder.getInstance().setEventPublisherService(eventPublisherService);
    }

    protected void unsetEventPublisherService(EventPublisherService eventPublisherService) {

        EventHookHandlerDataHolder.getInstance().setEventPublisherService(null);
    }
}
