package es.in2.verifier.model;

import lombok.Builder;

@Builder
public record GlobalErrorMessage(String title, String message, String path) { }