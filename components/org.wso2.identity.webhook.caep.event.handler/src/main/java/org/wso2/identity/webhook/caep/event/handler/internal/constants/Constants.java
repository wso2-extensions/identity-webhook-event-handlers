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

package org.wso2.identity.webhook.caep.event.handler.internal.constants;

public class Constants {

    public static final String EVENT_TIMESTAMP = "eventTimestamp";
    public static final String CREATED_TIMESTAMP = "createdTimestamp";
    public static final String UPDATED_TIMESTAMP = "updatedTimestamp";

    public static class CAEPFieldNames {

        public static final String EVENT_TIMESTAMP = "event_timestamp";
        public static final String INITIATING_ENTITY = "initiating_entity";
        public static final String REASON_ADMIN = "reason_admin";
        public static final String REASON_USER = "reason_user";
        public static final String CREDENTIAL_TYPE = "credential_type";
        public static final String CHANGE_TYPE = "change_type";
        public static final String FRIENDLY_NAME = "friendly_name";
        public static final String X509_ISSUER = "x509_issuer";
        public static final String X509_SERIAL = "x509_serial";
        public static final String FIDO_AAGUID = "fido_aaguid";
        public static final String FP_UA = "fp_ua";
        public static final String EXT_ID = "ext_id";
    }

    private Constants() {

    }

}
