package es.in2.verifier.domain.model.dto;

import lombok.Builder;

@Builder
public record GlobalErrorMessage(String title, String message, String path) { }