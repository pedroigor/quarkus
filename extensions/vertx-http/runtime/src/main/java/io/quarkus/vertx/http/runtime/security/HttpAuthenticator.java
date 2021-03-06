package io.quarkus.vertx.http.runtime.security;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.vertx.ext.web.RoutingContext;

/**
 * Class that is responsible for running the HTTP based authentication
 */
@ApplicationScoped
public class HttpAuthenticator {

    @Inject
    IdentityProviderManager identityProviderManager;

    final HttpAuthenticationMechanism mechanism;

    public HttpAuthenticator() {
        mechanism = null;
    }

    @Inject
    public HttpAuthenticator(Instance<HttpAuthenticationMechanism> instance,
            Instance<IdentityProvider<UsernamePasswordAuthenticationRequest>> usernamePassword) {
        if (instance.isResolvable()) {
            if (instance.isAmbiguous()) {
                throw new IllegalStateException("Multiple HTTP authentication mechanisms are not implemented yet, discovered "
                        + instance.stream().collect(Collectors.toList()));
            }
            mechanism = instance.get();
        } else {
            if (!usernamePassword.isUnsatisfied()) {
                //TODO: config
                mechanism = new BasicAuthenticationMechanism("Quarkus");
            } else {
                mechanism = null;
            }
        }
    }

    public HttpAuthenticator(HttpAuthenticationMechanism mechanism) {
        this.mechanism = mechanism;
    }

    /**
     * Attempts authentication with the contents of the request. If this is possible the CompletionStage
     * will resolve to a valid SecurityIdentity.
     *
     * If invalid credentials are present then the completion stage will resolve to a
     * {@link io.quarkus.security.AuthenticationFailedException}
     *
     * If no credentials are present it will resolve to null.
     */
    public CompletionStage<SecurityIdentity> attemptAuthentication(RoutingContext routingContext) {
        if (mechanism == null) {
            return CompletableFuture.completedFuture(null);
        }
        return mechanism.authenticate(routingContext, identityProviderManager);
    }

    /**
     *
     * @param closeTask The task that should be run to finalize the HTTP exchange.
     * @return
     */
    public CompletionStage<Void> sendChallenge(RoutingContext routingContext, Runnable closeTask) {
        if (closeTask == null) {
            closeTask = NoopCloseTask.INSTANCE;
        }
        if (mechanism == null) {
            routingContext.response().setStatusCode(HttpResponseStatus.FORBIDDEN.code());
            closeTask.run();
            return CompletableFuture.completedFuture(null);
        }
        return mechanism.sendChallenge(routingContext).thenRun(closeTask);
    }

    static class NoopCloseTask implements Runnable {

        static final NoopCloseTask INSTANCE = new NoopCloseTask();

        @Override
        public void run() {

        }
    }

}
