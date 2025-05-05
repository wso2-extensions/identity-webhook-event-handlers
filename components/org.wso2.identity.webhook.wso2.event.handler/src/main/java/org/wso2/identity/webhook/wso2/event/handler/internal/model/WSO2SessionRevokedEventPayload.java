package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.List;

public class WSO2SessionRevokedEventPayload extends WSO2BaseEventPayload {

    private String initiatorType;
    private String sessionId;
    private List<Application> applications = new ArrayList<>();

    private WSO2SessionRevokedEventPayload(Builder builder) {

        this.user = builder.user;
        this.tenant = builder.tenant;
        this.userResidentOrganization = builder.userResidentOrganization;
        this.userStore = builder.userStore;
        this.applications = builder.applications;
        this.initiatorType = builder.initiatorType;
        this.sessionId = builder.sessionId;
    }

    public String getInitiatorType() {

        return initiatorType;
    }

    public String getSessionId() {

        return sessionId;
    }

    public List<Application> getApplications() {

        return applications;
    }

    private WSO2SessionRevokedEventPayload() {

    }

    public static class Builder {

        private User user;
        private Organization tenant;
        private Organization userResidentOrganization;
        private UserStore userStore;
        private List<Application> applications;
        private String initiatorType;
        private String sessionId;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder sessionId(String sessionId) {

            this.sessionId = sessionId;
            return this;
        }

        public Builder user(User user) {

            this.user = user;
            return this;
        }

        public Builder tenant(Organization tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder userResidentOrganization(Organization userResidentOrganization) {

            this.userResidentOrganization = userResidentOrganization;
            return this;
        }

        public Builder userStore(UserStore userStore) {

            this.userStore = userStore;
            return this;
        }

        public Builder applications(List<Application> applications) {

            this.applications = applications;
            return this;
        }

        public WSO2SessionRevokedEventPayload build() {

            return new WSO2SessionRevokedEventPayload(this);
        }
    }
}
