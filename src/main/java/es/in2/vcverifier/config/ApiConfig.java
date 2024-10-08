package es.in2.vcverifier.config;

import es.in2.vcverifier.exception.InvalidSpringProfile;
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
            if (environment.getDefaultProfiles()[0] != null && !environment.getDefaultProfiles()[0].isBlank()){
                return environment.getDefaultProfiles()[0];
            }
        } else {
            log.debug(environment.getActiveProfiles()[0]);
            if (profiles.get(0) != null && !profiles.get(0).isBlank()){
                return profiles.get(0);
            }
        }
        throw new InvalidSpringProfile("An error occurred while trying to retrieve the current Spring Profile");
    }

}
