package io.quarkus.oidc.runtime;

import java.io.Serializable;
import java.util.logging.Level;

import org.eclipse.microprofile.config.spi.Converter;

public class SecretConverter implements Converter<Secret>, Serializable {
    
    @Override 
    public Secret convert(String value) {
        return new Secret(value);
    }
}
