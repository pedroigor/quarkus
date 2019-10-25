package io.quarkus.oidc.runtime;

import java.util.concurrent.CompletableFuture;

import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.oauth2.OAuth2Auth;
import io.vertx.ext.auth.oauth2.OAuth2ClientOptions;
import io.vertx.ext.auth.oauth2.providers.KeycloakAuth;

@Recorder
public class OidcRecorder {

    public void setup(OidcConfig config, RuntimeValue<Vertx> vertx, BeanContainer beanContainer) {
        OAuth2ClientOptions options = new OAuth2ClientOptions();

        // Base IDP server URL
        options.setSite(config.authServerUrl);
        // RFC7662 introspection service address
        if (config.introspectionPath.isPresent()) {
            options.setIntrospectionPath(config.introspectionPath.get());
        }

        // RFC7662 JWKS service address
        if (config.jwksPath.isPresent()) {
            options.setJwkPath(config.jwksPath.get());
        }

        if (config.clientId.isPresent()) {
            options.setClientID(config.clientId.get());
        }

        if (config.credentials.secret.isPresent()) {
            options.setClientSecret(config.credentials.secret.get());
        }
        if (config.publicKey.isPresent()) {
            options.addPubSecKey(new PubSecKeyOptions()
                    .setAlgorithm("RS256")
                    .setPublicKey(config.publicKey.get()));
        }

        CompletableFuture<OAuth2Auth> cf = new CompletableFuture<>();
        KeycloakAuth.discover(vertx.getValue(), options, new Handler<AsyncResult<OAuth2Auth>>() {
            @Override
            public void handle(AsyncResult<OAuth2Auth> event) {
                if (event.failed()) {
                    cf.completeExceptionally(event.cause());
                } else {
                    cf.complete(event.result());
                }
            }
        });

        OAuth2Auth auth = cf.join();
        beanContainer.instance(OidcIdentityProvider.class).setAuth(auth);
        AbstractOidcAuthenticationMechanism mechanism = null;
        
        if (OidcConfig.ClientType.SERVICE.equals(config.clientType)) {
            mechanism = beanContainer.instance(BearerAuthenticationMechanism.class);
        } else if (OidcConfig.ClientType.WEB_APP.equals(config.clientType)) {
            mechanism = beanContainer.instance(CodeAuthenticationMechanism.class);
        }
        
        mechanism.setAuth(auth, vertx.getValue());
    }
}
