package org.wso2.identity.webhook.wso2.event.handler.internal.model.common;

import java.util.Map;

public class Reason {
    private String id;
    private String message;
    private Map<String, Object> context;

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getMessage() {
        return message;
    }
    public void setMessage(String message) {
        this.message = message;
    }
    public Map<String, Object> getContext() {
        return context;
    }
    public void setContext(Map<String, Object> context) {
        this.context = context;
    }
}
