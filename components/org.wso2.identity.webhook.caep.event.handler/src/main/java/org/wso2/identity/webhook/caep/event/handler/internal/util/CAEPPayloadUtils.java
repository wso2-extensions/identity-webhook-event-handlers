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

package org.wso2.identity.webhook.caep.event.handler.internal.util;

import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.identity.webhook.common.event.handler.api.constants.Constants;
import org.wso2.identity.webhook.common.event.handler.api.model.EventMetadata;

import java.util.Objects;

public class CAEPPayloadUtils {

    /**
     * Resolve the event metadata based on the event name.
     *
     * @param eventName Event name.
     * @return Event metadata containing event and channel information.
     */
    public static EventMetadata resolveEventHandlerKey(String eventName) {

        String event = null;
        String channel = null;
        if (Objects.requireNonNull(eventName).equals(
                IdentityEventConstants.Event.USER_SESSION_TERMINATE)) {
            channel = Constants.Channel.SESSION_CHANNEL;
            event = Constants.Event.SESSION_REVOKED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_CREATE.equals(eventName)) {
            channel = Constants.Channel.SESSION_CHANNEL;
            event = Constants.Event.SESSION_CREATED_EVENT;
        } else if (IdentityEventConstants.Event.SESSION_EXTEND.equals(eventName) ||
                IdentityEventConstants.Event.SESSION_UPDATE.equals(eventName)) {
            channel = Constants.Channel.SESSION_CHANNEL;
            event = Constants.Event.SESSION_PRESENTED_EVENT;
        }

        return EventMetadata.builder()
                .event(String.valueOf(event))
                .channel(String.valueOf(channel))
                .eventProfile(Constants.EventSchema.CAEP.name())
                .build();
    }
}
