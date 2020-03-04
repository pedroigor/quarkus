package io.quarkus.oidc.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;

@ConfigGroup
public class Jwt {

    /**
     * If provided, indicates that JWT is signed with a client secret
     */
    @ConfigItem
    protected Optional<String> secret;

    /**
     * The algorithm to use to sign the JWT if {@code secret} is provided.
     */
    @ConfigItem
    protected Optional<String> algorithm;

    /**
     * If provided, indicates that JWT is signed using a private key from a key store
     */
    @ConfigItem
    protected Optional<PrivateKey> keyStore;

}
