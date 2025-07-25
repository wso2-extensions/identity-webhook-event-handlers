/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

public class AccessToken {

    private String tokenType;
    private String iat;
    private String jti;
    private String grantType;

    public String getTokenType() {

        return tokenType;
    }

    public String getIat() {

        return iat;
    }

    public String getJti() {

        return jti;
    }

    public String getGrantType() {

        return grantType;
    }

    private AccessToken(Builder builder) {

        this.tokenType = builder.tokenType;
        this.iat = builder.iat;
        this.jti = builder.jti;
        this.grantType = builder.grantType;
    }

    public static class Builder {

        private String tokenType;
        private String iat;
        private String jti;
        private String grantType;

        public Builder tokenType(String tokenType) {

            this.tokenType = tokenType;
            return this;
        }

        public Builder iat(String iat) {

            this.iat = iat;
            return this;
        }

        public Builder jti(String jti) {

            this.jti = jti;
            return this;
        }

        public Builder grantType(String grantType) {

            this.grantType = grantType;
            return this;
        }

        public AccessToken build() {

            return new AccessToken(this);
        }
    }
}
