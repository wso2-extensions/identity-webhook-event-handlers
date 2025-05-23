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

package org.wso2.identity.webhook.caep.event.handler.internal.utils;

import org.wso2.carbon.identity.core.context.model.Flow;

import java.util.Map;

import static org.wso2.identity.webhook.caep.event.handler.internal.constants.Constants.EVENT_TIMESTAMP;

public class CAEPEventUtils {

    public static long extractEventTimeStamp(Map<String, Object> params) {

        return params.containsKey(EVENT_TIMESTAMP) ?
                Long.parseLong(params.get(EVENT_TIMESTAMP).toString()) :
                System.currentTimeMillis();
    }

    public static String extractInitiatingEntity(Flow.InitiatingPersona persona) {

        switch (persona) {
            case ADMIN:
                return "admin";
            case USER:
                return "user";
            // Due to CAEP spec definitions, SYSTEM and APPLICATION are mapped to policy and system respectively.
            case SYSTEM:
                return "policy";
            case APPLICATION:
                return "system";
            default:
                return null;
        }
    }

}
