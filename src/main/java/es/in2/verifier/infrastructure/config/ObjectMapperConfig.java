package es.in2.verifier.infrastructure.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ObjectMapperConfig {

    private static final ObjectMapper OBJECT_MAPPER =
            JsonMapper.builder()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                    .serializationInclusion(JsonInclude.Include.NON_NULL)
                    .build();

    @Bean
    public ObjectMapper objectMapper() {
        return OBJECT_MAPPER;
    }

}
