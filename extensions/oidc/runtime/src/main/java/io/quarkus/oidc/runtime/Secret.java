package io.quarkus.oidc.runtime;

import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigItem;

public class Secret {

    public Secret(String value) {
        this.secret = Optional.of(value);
    }

    public static enum Method {
        BASIC,
        POST
    }

    @ConfigItem(name = ConfigItem.PARENT)
    protected Optional<String> secret;

    @ConfigItem(defaultValue = "BASIC")
    Method method;
}
