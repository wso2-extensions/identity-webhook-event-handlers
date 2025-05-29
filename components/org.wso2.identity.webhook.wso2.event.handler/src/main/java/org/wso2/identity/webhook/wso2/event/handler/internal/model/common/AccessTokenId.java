package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

public class AccessTokenId {

    private String tokenType;
    private String iss;
    private String jti;

    public AccessTokenId(String tokenType, String jti, String iss) {

        this.tokenType = tokenType;
        this.jti = jti;
        this.iss = iss;
    }

    public String getTokenType() {

        return tokenType;
    }

    public void setTokenType(String tokenType) {

        this.tokenType = tokenType;
    }

    public String getIss() {

        return iss;
    }

    public void setIss(String iss) {

        this.iss = iss;
    }

    public String getJti() {

        return jti;
    }

    public void setJti(String jti) {

        this.jti = jti;
    }
}
