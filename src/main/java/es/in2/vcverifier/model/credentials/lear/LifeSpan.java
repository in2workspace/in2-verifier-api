package es.in2.vcverifier.model.credentials.lear;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LifeSpan(
        @JsonProperty("end_date_time") String endDateTime,
        @JsonProperty("start_date_time") String startDateTime
) {}

