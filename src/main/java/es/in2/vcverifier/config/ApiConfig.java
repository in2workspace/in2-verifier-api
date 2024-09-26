package es.in2.vcverifier.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.util.List;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class ApiConfig {

    private final Environment environment;

    public String getCurrentEnvironment() {
        List<String> profiles = List.of(environment.getActiveProfiles());
        if (profiles.isEmpty()) {
            log.debug(environment.getDefaultProfiles()[0]);
            return environment.getDefaultProfiles()[0];
        } else {
            log.debug(environment.getActiveProfiles()[0]);
            return profiles.get(0);
        }
    }
}
