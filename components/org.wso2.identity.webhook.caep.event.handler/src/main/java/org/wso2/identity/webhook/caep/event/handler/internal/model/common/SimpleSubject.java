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

package org.wso2.identity.webhook.caep.event.handler.internal.model.common;

public class SimpleSubject extends Subject {

    private SimpleSubject() {

    }

    public static SimpleSubject createEmailSubject(String email) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("email");
        subject.addProperty("email", email);
        return subject;
    }

    public static SimpleSubject createPhoneSubject(String phoneNumber) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("phone_number");
        subject.addProperty("phone_number", phoneNumber);
        return subject;
    }

    public static SimpleSubject createAccountSubject(String uri) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("account");
        subject.addProperty("uri", uri);
        return subject;
    }

    public static SimpleSubject createIssSubSubject(String iss, String sub) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("iss_sub");
        subject.addProperty("iss", iss);
        subject.addProperty("sub", sub);
        return subject;
    }

    public static SimpleSubject createOpaqueSubject(String id) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("opaque");
        subject.addProperty("id", id);
        return subject;
    }

    public static SimpleSubject createDIDSubject(String url) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("did");
        subject.addProperty("did", url);
        return subject;
    }

    public static SimpleSubject createURISubject(String uri) {

        SimpleSubject subject = new SimpleSubject();
        subject.setFormat("uri");
        subject.addProperty("uri", uri);
        return subject;
    }

}
