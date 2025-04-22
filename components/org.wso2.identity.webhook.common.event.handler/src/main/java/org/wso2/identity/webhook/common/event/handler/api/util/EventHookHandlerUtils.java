/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.identity.webhook.common.event.handler.api.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.identity.webhook.common.event.handler.internal.util.EventHookHandlerInternalUtils;

/**
 * This class contains the utility method implementations.
 */
public class EventHookHandlerUtils {

    private static final Log log = LogFactory.getLog(EventHookHandlerUtils.class);
    private static volatile EventHookHandlerUtils instance;

    private EventHookHandlerUtils() {}

    public static EventHookHandlerUtils getInstance() {

        if (instance == null) {
            synchronized (EventHookHandlerUtils.class) {
                if (instance == null) {
                    instance = new EventHookHandlerUtils();
                }
            }
        }
        return instance;
    }

    /**
     * Get the tenant qualified URL with path.
     *
     * @param endpoint Endpoint.
     * @return Tenant qualified URL.
     */
    public String constructFullURLWithEndpoint(String endpoint) {
        if (endpoint == null) {
            throw new IllegalArgumentException("Endpoint cannot be null.");
        }
        endpoint = EventHookHandlerInternalUtils.getInstance().constructBaseURL() + endpoint;
        return endpoint;
    }

}
