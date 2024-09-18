package es.in2.vcverifier.config;

import lombok.Getter;
import org.springframework.stereotype.Component;

import java.util.HashSet;

@Getter
@Component
public class JtiTokenCache {

    private final HashSet<String> jtiTokenCache;

    public JtiTokenCache(HashSet<String> jtiCache) {
        this.jtiTokenCache = jtiCache;
    }

    public boolean addJti(String jti) {
        return jtiTokenCache.add(jti);
    }

    public boolean isJtiPresent(String jti) {
        return jtiTokenCache.contains(jti);
    }

}
