package com.hjson.websocket_rest_test.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class GlobalException extends RuntimeException {
    private ErrorCode errorCode;
    private String message;
}
