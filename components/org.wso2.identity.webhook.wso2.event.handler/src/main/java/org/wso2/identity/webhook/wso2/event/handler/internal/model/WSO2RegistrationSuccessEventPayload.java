package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

public class WSO2RegistrationSuccessEventPayload extends WSO2BaseEventPayload {
    private String initiatorType;
    private String action;
    private List<String> registrationMethods;
    private List<String> credentialsEnrolled;


    private WSO2RegistrationSuccessEventPayload(Builder builder) {
        this.user = builder.user;
        this.tenant = builder.tenant;
        this.userResidentOrganization = builder.userResidentOrganization;
        this.userStore = builder.userStore;
        this.application = builder.application;
        this.initiatorType = builder.initiatorType;
        this.action = builder.action;
        this.registrationMethods = builder.registrationMethods;
        this.credentialsEnrolled = builder.credentialsEnrolled;
    }

    public String getInitiatorType() {
        return initiatorType;
    }

    public String getAction() {
        return action;
    }

    public List<String> getRegistrationMethods() {
        return registrationMethods;
    }

    public List<String> getCredentialsEnrolled() {
        return credentialsEnrolled;
    }

    public static class Builder {
        private User user;
        private Organization tenant;
        private Organization userResidentOrganization;
        private UserStore userStore;
        private Application application;
        private String initiatorType;
        private String action;
        private List<String> registrationMethods;
        private List<String> credentialsEnrolled;

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

        public Builder registrationMethods(List<String> registrationMethods) {
            this.registrationMethods = registrationMethods;
            return this;
        }

        public Builder credentialsEnrolled(List<String> credentialsEnrolled) {
            this.credentialsEnrolled = credentialsEnrolled;
            return this;
        }

        public WSO2RegistrationSuccessEventPayload build() {
            return new WSO2RegistrationSuccessEventPayload(this);
        }
    }
}
