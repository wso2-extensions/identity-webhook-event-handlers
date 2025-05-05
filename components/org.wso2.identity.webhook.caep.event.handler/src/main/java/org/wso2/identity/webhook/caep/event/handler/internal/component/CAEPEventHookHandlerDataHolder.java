package org.wso2.identity.webhook.caep.event.handler.internal.component;

import org.wso2.carbon.identity.organization.management.service.OrganizationManager;

/**
 * A data holder class to keep the data of the event handler component.
 */
public class CAEPEventHookHandlerDataHolder {

    private static CAEPEventHookHandlerDataHolder instance = new CAEPEventHookHandlerDataHolder();
    private OrganizationManager organizationManager;

    private CAEPEventHookHandlerDataHolder() {

    }

    public static CAEPEventHookHandlerDataHolder getInstance() {

        return instance;
    }

}
