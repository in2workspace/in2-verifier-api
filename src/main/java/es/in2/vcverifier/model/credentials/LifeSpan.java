package es.in2.vcverifier.model.credentials;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record LifeSpan(
        @JsonProperty("end_date_time") String endDateTime,
        @JsonProperty("start_date_time") String startDateTime
) {}