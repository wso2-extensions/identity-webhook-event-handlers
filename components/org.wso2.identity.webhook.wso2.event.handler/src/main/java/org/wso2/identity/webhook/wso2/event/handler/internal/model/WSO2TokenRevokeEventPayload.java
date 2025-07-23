package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessToken;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

import java.util.List;

public class WSO2TokenRevokeEventPayload extends WSO2BaseEventPayload {

    private List<AccessToken> accessTokens;

    public List<AccessToken> getAccessTokens() {

        return accessTokens;
    }

    private WSO2TokenRevokeEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.tenant = builder.tenant;
        this.userStore = builder.userStore;
        this.user = builder.user;
        this.accessTokens = builder.accessTokens;
        this.application = builder.application;
    }

    public static class Builder {

        private String initiatorType;
        private Organization tenant;
        private UserStore userStore;
        private User user;
        private List<AccessToken> accessTokens;
        private Application application;

        public Builder initiatorType(String initiatorType) {

            this.initiatorType = initiatorType;
            return this;
        }

        public Builder tenant(Organization tenant) {

            this.tenant = tenant;
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

        public Builder accessTokens(List<AccessToken> accessTokens) {

            this.accessTokens = accessTokens;
            return this;
        }

        public Builder application(Application application) {

            this.application = application;
            return this;
        }

        public WSO2TokenRevokeEventPayload build() {

            return new WSO2TokenRevokeEventPayload(this);
        }
    }
}
