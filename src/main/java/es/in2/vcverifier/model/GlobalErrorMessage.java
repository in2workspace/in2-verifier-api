package es.in2.vcverifier.model;

import lombok.Builder;

@Builder
public record GlobalErrorMessage(String title, String message, String path) { }