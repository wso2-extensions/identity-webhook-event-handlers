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

    /**
     * Get {@link OrganizationManager}.
     *
     * @return organization manager instance {@link OrganizationManager}.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set {@link OrganizationManager}.
     *
     * @param organizationManager Instance of {@link OrganizationManager}.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }

}
