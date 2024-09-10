package es.in2.vcverifier.config;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import lombok.RequiredArgsConstructor;

import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;

@RequiredArgsConstructor
public class CacheStore<T> {

    private final Cache<String, T> cache;

    public CacheStore(long expiryDuration, TimeUnit timeUnit) {
        this.cache = CacheBuilder.newBuilder()
                .expireAfterWrite(expiryDuration, timeUnit)
                .concurrencyLevel(Runtime.getRuntime().availableProcessors())
                .build();
    }

    // Obtener el valor directamente sin Mono
    public T get(String key) {
        T value = cache.getIfPresent(key);
        if (value != null) {
            return value;
        } else {
            throw new NoSuchElementException("Value is not present.");
        }
    }

    // Eliminar un valor de la caché sin Mono
    public void delete(String key) {
        cache.invalidate(key);
    }

    // Añadir un valor a la caché sin Mono
    public String add(String key, T value) {
        if (key != null && !key.trim().isEmpty() && value != null) {
            cache.put(key, value);
            return key;
        }
        return null;  // Retornar null para indicar que no se agregó nada
    }
}

