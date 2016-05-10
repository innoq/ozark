/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2014-2015 Oracle and/or its affiliates. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License.  You can
 * obtain a copy of the License at
 * http://glassfish.java.net/public/CDDL+GPL_1_1.html
 * or packager/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at packager/legal/LICENSE.txt.
 *
 * GPL Classpath Exception:
 * Oracle designates this particular file as subject to the "Classpath"
 * exception as provided by Oracle in the GPL Version 2 section of the License
 * file that accompanied this code.
 *
 * Modifications:
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * "Portions Copyright [year] [name of copyright owner]"
 *
 * Contributor(s):
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */
package org.glassfish.ozark.security;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Alternative;
import javax.inject.Inject;
import javax.mvc.security.Csrf;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.NewCookie;
import java.io.Serializable;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

/**
 * Alternate implementation of javax.mvc.security.Csrf storing the token in a cookie
 * instead of HTTP session. Using this implementation an application can stay completely stateless.
 *
 * See https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29_Prevention_Cheat_Sheet#General_Recommendation:_Synchronizer_Token_Pattern
 * @author Oliver Tigges
 */
@RequestScoped
@Alternative
public class CookieBasedCsrfProtection implements Csrf, Serializable {

    public static final int MAX_AGE = 3600;
    public static final String COOKIE_NAME = "CsrfToken";
    private static final String HEADER_SET_COOKIE = "Set-Cookie";

    private static final long serialVersionUID = 1141322317114165983L;

    private String token;

    @Inject
    private HttpServletRequest request;

    @Context
    private HttpServletResponse response;

    @PostConstruct
    private void init() {
        final Optional<Cookie> cookie = findCookie();
        this.token = cookie.map(Cookie::getValue).orElse(UUID.randomUUID().toString());
        if (!cookie.isPresent()) {
            setCookie();
        }
    }

    public String getName() {
        return COOKIE_NAME;
    }

    public String getToken() {
        return token;
    }

    private Optional<Cookie> findCookie() {
        if (request.getCookies() == null) {
            return Optional.empty();
        }
        return Arrays.stream(request.getCookies()).filter(
                c -> COOKIE_NAME.equals(c.getName())).findFirst();
    }

    private void setCookie() {
        final NewCookie cookie = new NewCookie(COOKIE_NAME, token, null, null, null, MAX_AGE, request.isSecure());
        response.addHeader(HEADER_SET_COOKIE, cookie.toString());
    }

}
