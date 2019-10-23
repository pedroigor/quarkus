package io.quarkus.vertx.http.runtime.security;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.function.BiFunction;
import java.util.function.Supplier;

import javax.enterprise.inject.spi.CDI;

import io.quarkus.arc.runtime.BeanContainer;
import io.quarkus.arc.runtime.BeanContainerListener;
import io.quarkus.runtime.ExecutorRecorder;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

@Recorder
public class HttpSecurityRecorder {

    private static final AuthenticationRequestContext blockingRequestContext = new AuthenticationRequestContext<SecurityIdentity>() {
        @Override
        public CompletionStage<SecurityIdentity> runBlocking(Supplier<SecurityIdentity> function) {
            CompletableFuture<SecurityIdentity> ret = new CompletableFuture<>();
            try {
                SecurityIdentity result = function.get();
                ret.complete(result);
            } catch (Throwable t) {
                ret.completeExceptionally(t);
            }
            return ret;
        }
    };

    public Handler<RoutingContext> authenticationMechanismHandler() {
        return new Handler<RoutingContext>() {

            volatile HttpAuthenticator authenticator;

            @Override
            public void handle(RoutingContext event) {
                if (authenticator == null) {
                    authenticator = CDI.current().select(HttpAuthenticator.class).get();
                }
                //we put the authenticator into the routing context so it can be used by other systems
                event.put(HttpAuthenticator.class.getName(), authenticator);
                authenticator.attemptAuthentication(event).handle(new BiFunction<SecurityIdentity, Throwable, Object>() {
                    @Override
                    public Object apply(SecurityIdentity identity, Throwable throwable) {
                        if (throwable != null) {
                            while (throwable instanceof CompletionException && throwable.getCause() != null) {
                                throwable = throwable.getCause();
                            }
                            //auth failed
                            if (throwable instanceof AuthenticationFailedException) {
                                authenticator.sendChallenge(event, new Runnable() {
                                    @Override
                                    public void run() {
                                        event.response().end();
                                    }
                                });
                            } else {
                                event.fail(throwable);
                            }
                            return null;
                        }
                        if (identity != null) {
                            event.setUser(new QuarkusHttpUser(identity));
                        }
                        event.next();
                        return null;
                    }
                });
            }
        };
    }

    public Handler<RoutingContext> permissionCheckHandler() {
        return new Handler<RoutingContext>() {
            volatile HttpAuthorizer authorizer;

            @Override
            public void handle(RoutingContext event) {
                if (authorizer == null) {
                    authorizer = CDI.current().select(HttpAuthorizer.class).get();
                }
                authorizer.checkPermission(event, new AsyncAuthenticationRequestContext())
                        .handle(new BiFunction<SecurityIdentity, Throwable, SecurityIdentity>() {
                            @Override
                            public SecurityIdentity apply(SecurityIdentity identity, Throwable throwable) {
                                if (throwable != null) {
                                    event.fail(throwable);
                                    return null;
                                }
                                if (identity != null) {
                                    event.setUser(new QuarkusHttpUser(identity));
                                    event.next();
                                    return identity;
                                }
                                event.response().end();
                                return null;
                            }
                        });
            }
        };
    }

    public BeanContainerListener initPermissions(HttpBuildTimeConfig permissions,
            Map<String, Supplier<HttpSecurityPolicy>> policies) {
        return new BeanContainerListener() {
            @Override
            public void created(BeanContainer container) {
                container.instance(HttpAuthorizer.class).init(permissions, policies);
            }
        };
    }

    private class AsyncAuthenticationRequestContext implements AuthenticationRequestContext<SecurityIdentity> {

        private boolean inBlocking = false;

        @Override
        public CompletionStage<SecurityIdentity> runBlocking(Supplier<SecurityIdentity> function) {
            if (inBlocking) {
                return blockingRequestContext.runBlocking(function);
            }

            return CompletableFuture.supplyAsync(new Supplier<SecurityIdentity>() {
                @Override
                public SecurityIdentity get() {
                    try {
                        inBlocking = true;
                        return function.get();
                    } finally {
                        inBlocking = false;
                    }
                }
            }, ExecutorRecorder.getCurrent());
        }
    }
}
