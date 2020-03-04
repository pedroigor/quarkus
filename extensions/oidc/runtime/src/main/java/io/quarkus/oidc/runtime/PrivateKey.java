package io.quarkus.oidc.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigGroup;
import io.quarkus.runtime.annotations.ConfigItem;

@ConfigGroup
public class PrivateKey {

    /**
     * The key store file
     */
    @ConfigItem
    protected String file;

    /**
     * The key store password
     */
    @ConfigItem
    protected String password;

    /**
     * The key in the key store referencing the private key
     */
    @ConfigItem
    protected Optional<String> key;

    /**
     * The key password
     */
    @ConfigItem
    protected Optional<String> keyPassword;
}
