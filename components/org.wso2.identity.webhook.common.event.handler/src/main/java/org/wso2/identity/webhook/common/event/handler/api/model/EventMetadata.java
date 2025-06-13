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

package org.wso2.identity.webhook.common.event.handler.api.model;

/**
 * Event metadata model.
 */
public class EventMetadata {

    private final String eventProfile;
    private final String channel;
    private final String event;

    private EventMetadata(Builder builder) {

        this.eventProfile = builder.eventProfile;
        this.channel = builder.channel;
        this.event = builder.event;
    }

    public String getEventProfile() {

        return eventProfile;
    }

    public String getChannel() {

        return channel;
    }

    public String getEvent() {

        return event;
    }

    public static Builder builder() {

        return new Builder();
    }

    /**
     * Builder class to build EventMetadata.
     */
    public static class Builder {

        private String eventProfile;
        private String channel;
        private String event;

        public Builder eventProfile(String eventProfile) {

            this.eventProfile = eventProfile;
            return this;
        }

        public Builder channel(String channel) {

            this.channel = channel;
            return this;
        }

        public Builder event(String event) {

            this.event = event;
            return this;
        }

        public EventMetadata build() {

            return new EventMetadata(this);
        }
    }
}
