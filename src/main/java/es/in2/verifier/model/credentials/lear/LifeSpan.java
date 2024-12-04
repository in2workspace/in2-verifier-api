package es.in2.verifier.model.credentials.lear;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record LifeSpan(
        @JsonProperty("end_date_time") String endDateTime,
        @JsonProperty("start_date_time") String startDateTime
) {}

