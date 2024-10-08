package es.in2.vcverifier.exception.handler;

import lombok.Builder;

@Builder
public record GlobalErrorMessage(String title, String message, String path) { }