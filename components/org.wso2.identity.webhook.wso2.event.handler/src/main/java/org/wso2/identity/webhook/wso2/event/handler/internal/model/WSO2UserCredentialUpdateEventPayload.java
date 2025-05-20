package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

public class WSO2UserCredentialUpdateEventPayload extends WSO2BaseEventPayload {

    private String credentialType;
    private String action;

    private WSO2UserCredentialUpdateEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.credentialType = builder.credentialType;
        this.action = builder.action;
        this.organization = builder.organization;
        this.userStore = builder.userStore;
        this.user = builder.user;
    }

    public String getAction() {

        return action;
    }

    public String getCredentialType() {

        return credentialType;
    }

    public static class Builder {

        private String initiatorType;
        private Organization organization;
        private UserStore userStore;
        private User user;
        private String credentialType;
        private String action;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
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

        public Builder credentialType(String credentialType) {

            this.credentialType = credentialType;
            return this;
        }

        public Builder action(String action) {

            this.action = action;
            return this;
        }

        public WSO2UserCredentialUpdateEventPayload build() {

            return new WSO2UserCredentialUpdateEventPayload(this);
        }
    }
}
