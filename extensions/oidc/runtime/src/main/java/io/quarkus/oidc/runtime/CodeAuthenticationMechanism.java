package io.quarkus.oidc.runtime;

import javax.enterprise.context.ApplicationScoped;
import java.net.URI;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.vertx.core.Handler;
import io.vertx.core.http.Cookie;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.oauth2.AccessToken;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.impl.CookieImpl;

@ApplicationScoped
public class CodeAuthenticationMechanism extends AbstractOidcAuthenticationMechanism {

    private static final String STATE_COOKIE_NAME = "q_auth";
    private static final String SESSION_COOKIE_NAME = "q_session";

    @Override
    public CompletionStage<SecurityIdentity> authenticate(RoutingContext context,
            IdentityProviderManager identityProviderManager) {
        Cookie sessionCookie = context.request().getCookie(SESSION_COOKIE_NAME);

        // if session already established, try to re-authenticate
        if (sessionCookie != null) {
            String idToken = sessionCookie.getValue();

            if (true) {
                return reAuthenticateIfSessionStillActive(identityProviderManager, idToken);
            }

            return reAuthenticate(identityProviderManager, idToken);
        }

        // start a new session by starting the code flow dance
        return performCodeFlow(identityProviderManager, context);
    }

    @Override
    public CompletionStage<ChallengeData> getChallenge(RoutingContext context) {
        removeSessionCookie(context);
        ChallengeData challenge;

        JsonObject params = new JsonObject();

        params.put("scopes", new JsonArray(Arrays.asList("openid")));
        params.put("redirect_uri", buildRedirectUri(context));
        params.put("state", generateState(context));

        challenge = new ChallengeData(HttpResponseStatus.FOUND.code(), HttpHeaders.LOCATION, auth.authorizeURL(params));

        return CompletableFuture.completedFuture(challenge);
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

                reAuthenticate(identityProviderManager, result.opaqueIdToken())
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

    private CompletionStage<SecurityIdentity> reAuthenticateIfSessionStillActive(
            IdentityProviderManager identityProviderManager, String idToken) {
        return reAuthenticate(identityProviderManager, idToken).thenCompose(
                new Function<SecurityIdentity, CompletionStage<SecurityIdentity>>() {
                    @Override
                    public CompletionStage<SecurityIdentity> apply(SecurityIdentity securityIdentity) {
                        CompletableFuture<SecurityIdentity> cf = new CompletableFuture<>();
                        JsonObject params = new JsonObject();

                        params.put("id_token_hint", idToken);
                        params.put("prompt", "none");

                        vertx.createHttpClient()
                                .requestAbs(HttpMethod.GET, auth.authorizeURL(params), new Handler<HttpClientResponse>() {
                                    @Override
                                    public void handle(HttpClientResponse event) {
                                        String location = event.headers().get(HttpHeaderNames.LOCATION);

                                        if (!location.contains("code=")) {
                                            cf.completeExceptionally(new AuthenticationFailedException());
                                            return;
                                        }

                                        cf.complete(securityIdentity);
                                    }
                                }).exceptionHandler(new Handler<Throwable>() {
                            @Override
                            public void handle(Throwable event) {
                                cf.completeExceptionally(event);
                            }
                        }).end();

                        return cf;
                    }
                });
    }

    private void removeSessionCookie(RoutingContext context) {
        context.response().removeCookie(SESSION_COOKIE_NAME, true);
    }
}
