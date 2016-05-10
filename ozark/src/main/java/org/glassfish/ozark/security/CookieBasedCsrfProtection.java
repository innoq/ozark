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
 */
@RequestScoped
@Alternative
public class CookieBasedCsrfProtection implements Csrf, Serializable {

    public static final int MAX_AGE = 3600;
    public static final String COOKIE_NAME = "CsrfToken";

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
        return Arrays.stream(request.getCookies()).filter(
                c -> c.getName().equals(COOKIE_NAME)).findFirst();
    }

    private void setCookie() {
        final NewCookie cookie = new NewCookie(COOKIE_NAME, token, null, null, null, MAX_AGE, request.isSecure());
        response.addHeader("Set-Cookie", cookie.toString());
    }

}
