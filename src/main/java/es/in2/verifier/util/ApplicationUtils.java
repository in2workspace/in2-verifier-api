package es.in2.verifier.util;

import org.bouncycastle.util.encoders.UrlBase64;
import reactor.core.publisher.Mono;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class ApplicationUtils {

    private ApplicationUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static Mono<String> generateCustomNonce() {
        return convertUUIDToBytes(UUID.randomUUID())
                .map(uuidBytes -> new String(UrlBase64.encode(uuidBytes), StandardCharsets.UTF_8));
    }

    private static Mono<byte[]> convertUUIDToBytes(UUID uuid) {
        return Mono.fromSupplier(() -> {
            ByteBuffer byteBuffer = ByteBuffer.wrap(new byte[16]);
            byteBuffer.putLong(uuid.getMostSignificantBits());
            byteBuffer.putLong(uuid.getLeastSignificantBits());
            return byteBuffer.array();
        });
    }

}
