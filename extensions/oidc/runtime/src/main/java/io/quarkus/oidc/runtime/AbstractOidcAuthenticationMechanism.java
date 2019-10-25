package io.quarkus.oidc.runtime;

import java.util.concurrent.CompletionStage;

import io.quarkus.security.credential.TokenCredential;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.TokenAuthenticationRequest;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.oauth2.OAuth2Auth;

abstract class AbstractOidcAuthenticationMechanism implements HttpAuthenticationMechanism {

    protected static final String BEARER = "Bearer";

    protected volatile OAuth2Auth auth;
    protected Vertx vertx;

    public AbstractOidcAuthenticationMechanism setAuth(OAuth2Auth auth, Vertx vertx) {
        this.auth = auth;
        this.vertx = vertx;
        return this;
    }

    protected CompletionStage<SecurityIdentity> reAuthenticate(IdentityProviderManager identityProviderManager, String token) {
        return identityProviderManager.authenticate(new TokenAuthenticationRequest(new TokenCredential(token, BEARER)));
    }
}
