package io.quarkus.oidc.runtime;

import java.net.URI;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import javax.enterprise.context.ApplicationScoped;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TokenAuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.impl.CookieImpl;

@ApplicationScoped
public class OidcAuthenticationMechanism implements HttpAuthenticationMechanism {

    private static final String BEARER = "Bearer";
    private static final String STATE_COOKIE_NAME = "q_auth";
    private static final String SESSION_COOKIE_NAME = "q_session";

    private volatile OAuth2Auth auth;

    @Override
    public CompletionStage<SecurityIdentity> authenticate(RoutingContext context,
            IdentityProviderManager identityProviderManager) {
        String token = extractBearerToken(context);

        // if a bearer token is provided try to authenticate
        if (token != null) {
            return authenticate(identityProviderManager, token);
        }

        // if the application supports code flow
        if (supportsCodeFlow()) {
            Cookie sessionCookie = context.request().getCookie(SESSION_COOKIE_NAME);

            // if session already established, try to re-authenticate
            if (sessionCookie != null) {
                CompletionStage<SecurityIdentity> cf = authenticate(identityProviderManager,
                        sessionCookie.getValue());

                return cf.exceptionally(throwable -> {
                    context.response().removeCookie(SESSION_COOKIE_NAME);
                    return null;
                });
            }

            // start a new session by starting the code flow dance
            return performCodeFlow(identityProviderManager, context);
        }

        return notAuthorized();
    }

    @Override
    public CompletionStage<ChallengeData> getChallenge(RoutingContext context) {
        ChallengeData challenge;
        String bearerToken = extractBearerToken(context);

        if (supportsCodeFlow()) {
            JsonObject params = new JsonObject();

            params.put("scopes", new JsonArray(Arrays.asList("openid")));
            params.put("redirect_uri", buildRedirectUri(context));
            params.put("state", generateState(context));

            challenge = new ChallengeData(HttpResponseStatus.FOUND.code(), HttpHeaders.LOCATION, auth.authorizeURL(params));
        } else if (bearerToken == null) {
            challenge = new ChallengeData(HttpResponseStatus.UNAUTHORIZED.code(), null, null);
        } else {
            challenge = new ChallengeData(HttpResponseStatus.FORBIDDEN.code(), null, null);
        }

        return CompletableFuture.completedFuture(challenge);
    }

    private CompletionStage<SecurityIdentity> notAuthorized() {
        CompletableFuture<SecurityIdentity> cf = new CompletableFuture<>();

        cf.completeExceptionally(new AuthenticationFailedException());

        return cf;
    }

    public OidcAuthenticationMechanism setAuth(OAuth2Auth auth) {
        this.auth = auth;
        return this;
    }

    private CompletionStage<SecurityIdentity> performCodeFlow(IdentityProviderManager identityProviderManager,
            RoutingContext context) {
        CompletableFuture<SecurityIdentity> cf = new CompletableFuture<>();
        JsonObject params = new JsonObject();

        params.put("code", context.request().getParam("code"));
        params.put("redirect_uri", buildRedirectUri(context));

        auth.authenticate(params, userAsyncResult -> {
            if (userAsyncResult.failed()) {
                cf.completeExceptionally(new AuthenticationFailedException());
            } else {
                AccessToken result = AccessToken.class.cast(userAsyncResult.result());

                authenticate(identityProviderManager, result.opaqueIdToken())
                        .whenCompleteAsync((securityIdentity, throwable) -> {
                            if (throwable != null) {
                                cf.completeExceptionally(throwable);
                            } else {
                                processSuccessfulAuthentication(context, cf, result, securityIdentity);
                            }
                        });
            }
        });

        return cf;
    }

    private void processSuccessfulAuthentication(RoutingContext context, CompletableFuture<SecurityIdentity> cf,
            AccessToken result, SecurityIdentity securityIdentity) {
        context.response().removeCookie(STATE_COOKIE_NAME);

        CookieImpl cookie = new CookieImpl(SESSION_COOKIE_NAME, result.opaqueIdToken());

        cookie.setMaxAge(result.idToken().getInteger("exp"));
        cookie.setSecure(context.request().isSSL());
        cookie.setHttpOnly(true);

        context.response().addCookie(cookie);
        cf.complete(securityIdentity);
    }

    private CompletionStage<SecurityIdentity> authenticate(IdentityProviderManager identityProviderManager, String token) {
        return identityProviderManager.authenticate(new TokenAuthenticationRequest(new TokenCredential(token, BEARER)));
    }

    private String extractBearerToken(RoutingContext context) {
        final HttpServerRequest request = context.request();
        final String authorization = request.headers().get(HttpHeaders.AUTHORIZATION);

        if (authorization == null) {
            return null;
        }

        int idx = authorization.indexOf(' ');

        if (idx <= 0 || !BEARER.equalsIgnoreCase(authorization.substring(0, idx))) {
            return null;
        }

        String token = authorization.substring(idx + 1);
        return token;
    }

    private boolean supportsCodeFlow() {
        return true;
    }

    private String generateState(RoutingContext context) {
        CookieImpl cookie = new CookieImpl(STATE_COOKIE_NAME, UUID.randomUUID().toString());

        cookie.setHttpOnly(true);
        cookie.setSecure(context.request().isSSL());
        cookie.setMaxAge(-1);

        context.response().addCookie(cookie);

        return cookie.getValue();
    }

    private String buildRedirectUri(RoutingContext context) {
        URI absoluteUri = URI.create(context.request().absoluteURI());
        StringBuilder builder = new StringBuilder(context.request().scheme()).append("://")
                .append(absoluteUri.getAuthority())
                .append(absoluteUri.getPath());

        return builder.toString();
    }
}
