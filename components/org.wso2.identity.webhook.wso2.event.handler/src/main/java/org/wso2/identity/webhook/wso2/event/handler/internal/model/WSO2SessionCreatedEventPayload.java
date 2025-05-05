package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.ArrayList;
import java.util.List;

public class WSO2SessionCreatedEventPayload extends WSO2BaseEventPayload {

    private String sessionId;
    private String currentAcr;
    private List<String> authenticationMethods = new ArrayList<>();

    public String getSessionId() {

        return sessionId;
    }

    public String getCurrentAcr() {

        return currentAcr;
    }

    public List<String> getAuthenticationMethods() {

        return authenticationMethods;
    }

    private WSO2SessionCreatedEventPayload(Builder builder) {

        this.user = builder.user;
        this.tenant = builder.tenant;
        this.userResidentOrganization = builder.userResidentOrganization;
        this.userStore = builder.userStore;
        this.application = builder.application;
        this.sessionId = builder.sessionId;
        this.currentAcr = builder.currentAcr;
        this.authenticationMethods = builder.authenticationMethods;
    }

    private WSO2SessionCreatedEventPayload() {

    }

    public static class Builder {

        private String sessionId;
        private String currentAcr;
        private User user;
        private Organization tenant;
        private Organization userResidentOrganization;
        private UserStore userStore;
        private Application application;
        private List<String> authenticationMethods = new ArrayList<>();

        public Builder sessionId(String sessionId) {

            this.sessionId = sessionId;
            return this;
        }

        public Builder currentAcr(String currentAcr) {

            this.currentAcr = currentAcr;
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

        public Builder application(Application application) {

            this.application = application;
            return this;
        }

        public Builder authenticationMethods(List<String> authenticationMethods) {

            this.authenticationMethods = authenticationMethods;
            return this;
        }

        public WSO2SessionCreatedEventPayload build() {

            return new WSO2SessionCreatedEventPayload(this);
        }
    }

}
