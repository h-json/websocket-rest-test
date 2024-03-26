package com.hjson.websocket_rest_test.data.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ErrorResponse {
    private final String code;
    private final String httpStatus;
    private final String message;
}
