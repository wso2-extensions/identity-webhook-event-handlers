/*
 * Copyright (c) 2024-2025, WSO2 LLC. (http://www.wso2.com).
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
import org.wso2.carbon.identity.event.IdentityEventConfigBuilder;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.IdentityEventServerException;
import org.wso2.carbon.identity.event.bean.ModuleConfiguration;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.identity.event.common.publisher.EventPublisherService;
import org.wso2.identity.webhook.common.event.handler.EventConfigManager;
import org.wso2.identity.webhook.common.event.handler.LoginEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.UserOperationEventHookHandler;
import org.wso2.identity.webhook.common.event.handler.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.constant.Constants;
import org.wso2.identity.webhook.common.event.handler.util.EventHookHandlerUtils;

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
            String isLoginEventHandlerEnabled = getIdentityEventProperty(Constants.LOGIN_EVENT_HOOK_NAME,
                    Constants.LOGIN_EVENT_HOOK_ENABLED);
            String isUserOperationEventHandlerEnabled =
                    getIdentityEventProperty(Constants.USER_OPERATION_EVENT_HOOK_NAME,
                            Constants.USER_OPERATION_EVENT_HOOK_ENABLED);
            BundleContext bundleContext = context.getBundleContext();

            if (isLoginEventHandlerEnabled != null && isLoginEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new LoginEventHookHandler(EventHookHandlerUtils.getInstance(),
                                EventConfigManager.getInstance()), null);
            }
            if (isUserOperationEventHandlerEnabled != null && isUserOperationEventHandlerEnabled
                    .equalsIgnoreCase(Boolean.TRUE.toString())) {
                bundleContext.registerService(AbstractEventHandler.class.getName(),
                        new UserOperationEventHookHandler(EventHookHandlerUtils.getInstance(),
                                EventConfigManager.getInstance()), null);
            }
        } catch (IdentityEventServerException e) {
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
            name = "user.operation.event.payload.builder",
            service = UserOperationEventPayloadBuilder.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeUserOperationEventPayloadBuilder"
    )
    protected void addUserOperationEventPayloadBuilder(
            UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        log.debug("Adding the User Operation Event Payload Builder Service : " +
                userOperationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance().addUserOperationEventPayloadBuilder(userOperationEventPayloadBuilder);
    }

    protected void removeUserOperationEventPayloadBuilder(
            UserOperationEventPayloadBuilder userOperationEventPayloadBuilder) {

        log.debug("Removing the User Operation Event Payload Builder Service : " +
                userOperationEventPayloadBuilder.getEventSchemaType());
        EventHookHandlerDataHolder.getInstance()
                .removeUserOperationEventPayloadBuilder(userOperationEventPayloadBuilder);
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

    /**
     * Get the identity property specified in identity-event.properties
     *
     * @param moduleName   The name of the module which the property belongs to
     * @param propertyName The name of the property which should be fetched
     * @return The required property
     */
    private String getIdentityEventProperty(String moduleName, String propertyName)
            throws IdentityEventServerException {

        // Retrieving properties set in identity event properties
        String propertyValue = null;
        try {
            ModuleConfiguration moduleConfiguration = IdentityEventConfigBuilder.getInstance()
                    .getModuleConfigurations(moduleName);

            if (moduleConfiguration != null) {
                propertyValue = moduleConfiguration.getModuleProperties().getProperty(propertyName);
            }
        } catch (IdentityEventException e) {
            throw new IdentityEventServerException("An error occurred while retrieving module properties because " +
                    e.getMessage());
        }
        return propertyValue;
    }
}
