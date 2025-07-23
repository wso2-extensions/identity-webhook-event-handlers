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

    public AccessToken(String tokenType, String jti, String iat) {

        this.tokenType = tokenType;
        this.jti = jti;
        this.iat = iat;
    }

    public AccessToken(String tokenType, String iat) {

        this.tokenType = tokenType;
        this.iat = iat;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public String getIat() {

        return iat;
    }

    public void setIat(String iat) {

        this.iat = iat;
    }

    public String getJti() {

        return jti;
    }

    public void setJti(String jti) {

        this.jti = jti;
    }

    public String getGrantType() {

        return grantType;
    }

    public void setGrantType(String grantType) {

        this.grantType = grantType;
    }
}
