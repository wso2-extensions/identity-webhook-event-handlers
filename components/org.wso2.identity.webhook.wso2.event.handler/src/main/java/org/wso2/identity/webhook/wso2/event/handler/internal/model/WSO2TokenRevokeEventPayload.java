package org.wso2.identity.webhook.wso2.event.handler.internal.model;

import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.AccessTokenId;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Application;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.Organization;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.User;
import org.wso2.identity.webhook.wso2.event.handler.internal.model.common.UserStore;

public class WSO2TokenRevokeEventPayload extends WSO2BaseEventPayload {

    private AccessTokenId accessTokenId;

    public AccessTokenId getAccessTokenId() {

        return accessTokenId;
    }

    private WSO2TokenRevokeEventPayload(Builder builder) {

        this.initiatorType = builder.initiatorType;
        this.tenant = builder.tenant;
        this.userStore = builder.userStore;
        this.user = builder.user;
        this.accessTokenId = builder.accessTokenId;
        this.application = builder.application;
    }

    public static class Builder {

        private String initiatorType;
        private Organization tenant;
        private UserStore userStore;
        private User user;
        private AccessTokenId accessTokenId;
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

        public Builder accessTokenId(AccessTokenId accessTokenId) {

            this.accessTokenId = accessTokenId;
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
