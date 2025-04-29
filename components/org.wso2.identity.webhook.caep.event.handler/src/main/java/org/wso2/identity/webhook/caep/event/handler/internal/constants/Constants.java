package org.wso2.identity.webhook.caep.event.handler.internal.constants;

public class Constants {

    public enum InitiatingEntity {
        POLICY,
        SYSTEM,
        ADMIN,
        USER
    }

    public static class CAEPMapParams {

        public static final String INITIATING_ENTITY = "initiatingEntity";
        public static final String REASON_USER = "reasonUser";
        public static final String REASON_ADMIN = "reasonAdmin";
        public static final String EVENT_TIME_STAMP = "eventTimestamp";
    }

}
