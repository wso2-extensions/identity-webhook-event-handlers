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

package org.wso2.identity.webhook.wso2.event.handler.internal.component;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.identity.webhook.common.event.handler.api.builder.LoginEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.SessionEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.builder.UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.common.event.handler.api.util.SecurityEventTokenBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2LoginEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2SessionEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.builder.WSO2UserOperationEventPayloadBuilder;
import org.wso2.identity.webhook.wso2.event.handler.api.util.WSO2SecurityEventTokenBuilder;

/**
 * WSO2 Event Handler service component class.
 */
@Component(
        name = "org.wso2.identity.webhook.wso2.event.handler.internal.component.WSO2EventHookHandlerServiceComponent",
        immediate = true)
public class WSO2EventHookHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(WSO2EventHookHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {

        try {
            log.debug("WSO2 Event Handler is activated.");

            context.getBundleContext().registerService(LoginEventPayloadBuilder.class.getName(),
                    new WSO2LoginEventPayloadBuilder(), null);
            context.getBundleContext().registerService(UserOperationEventPayloadBuilder.class.getName(),
                    new WSO2UserOperationEventPayloadBuilder(), null);
            context.getBundleContext().registerService(SessionEventPayloadBuilder.class.getName(),
                    new WSO2SessionEventPayloadBuilder(), null);
            context.getBundleContext().registerService(SecurityEventTokenBuilder.class.getName(),
                    new WSO2SecurityEventTokenBuilder(), null);
        } catch (Exception e) {
            log.error("Error while activating event handler.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        log.debug("WSO2 Event Handler is deactivated.");
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(organizationManager);
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        WSO2EventHookHandlerDataHolder.getInstance().setOrganizationManager(null);
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        WSO2EventHookHandlerDataHolder.getInstance().setRealmService(null);
    }
}
