package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.*;

public class WSO2RegistrationFailedEventPayload extends WSO2BaseEventPayload {
    private String initiatorType;
    private String action;
    private Reason reason;

    private WSO2RegistrationFailedEventPayload(Builder builder) {
        this.user = builder.user;
        this.tenant = builder.tenant;
        this.userResidentOrganization = builder.userResidentOrganization;
        this.userStore = builder.userStore;
        this.application = builder.application;
        this.initiatorType = builder.initiatorType;
        this.action = builder.action;
        this.reason = builder.reason;
    }

    public String getInitiatorType() {
        return initiatorType;
    }

    public String getAction() {
        return action;
    }

    public Reason getReason() {
        return reason;
    }

    public static class Builder {
        private User user;
        private Organization tenant;
        private Organization userResidentOrganization;
        private UserStore userStore;
        private Application application;
        private String initiatorType;
        private String action;
        private Reason reason;

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

        public Builder application(Application application) {
            this.application = application;
            return this;
        }

        public Builder initiatorType(String initiatorType) {
            this.initiatorType = initiatorType;
            return this;
        }

        public Builder action(String action) {
            this.action = action;
            return this;
        }

        public Builder reason(Reason reason) {
            this.reason = reason;
            return this;
        }
    }
}
