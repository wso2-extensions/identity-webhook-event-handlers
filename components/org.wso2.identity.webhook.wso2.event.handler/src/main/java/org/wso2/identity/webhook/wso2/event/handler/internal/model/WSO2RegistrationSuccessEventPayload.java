package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

public class WSO2RegistrationSuccessEventPayload extends WSO2BaseEventPayload {

    private List<String> registrationMethods;
    private List<String> credentialsEnrolled;

    public List<String> getRegistrationMethods() {

        return registrationMethods;
    }

    public List<String> getCredentialsEnrolled() {

        return credentialsEnrolled;
    }

    private WSO2RegistrationSuccessEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.tenant = builder.tenant;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.user = builder.user;
        this.registrationMethods = builder.registrationMethods;
        this.credentialsEnrolled = builder.credentialsEnrolled;
    }

    public static class Builder {

        private String initiatorType;
        private Organization tenant;
        private Organization organization;
        private UserStore userStore;
        private User user;
        private List<String> registrationMethods;
        private List<String> credentialsEnrolled;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder tenant(Organization tenant) {

            this.tenant = tenant;
            return this;
        }

        public Builder organization(Organization organization) {

            this.organization = organization;
            return this;
        }

        public Builder userStore(UserStore userStore) {

            this.userStore = userStore;
            return this;
        }

        public Builder user(User user) {

            this.user = user;
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
