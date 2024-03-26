package com.hjson.websocket_rest_test.exception;

import com.hjson.websocket_rest_test.data.dto.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.InvalidDataAccessResourceUsageException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.sql.SQLSyntaxErrorException;

@RestControllerAdvice
public class GlobalExceptionHandler {
    Logger log = LoggerFactory.getLogger(this.getClass());

    @ExceptionHandler(value = GlobalException.class)
    public ResponseEntity<ErrorResponse> handleBlockoliException(GlobalException e) {
        ErrorCode errorCode = e.getErrorCode();

        log.error(e.getMessage(), e);

        final ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), e.getMessage());
        return new ResponseEntity<>(errorResponse, e.getErrorCode().getHttpStatus());
    }

    @ExceptionHandler(value = HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException(HttpMessageNotReadableException e) {
        ErrorCode errorCode = ErrorCode.JSON_PARSE_FAILED;
        log.error(e.getMessage(), e);
        final ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), "요청 JSON 해석 오류");
        return new ResponseEntity<>(errorResponse, errorCode.getHttpStatus());
    }

    @ExceptionHandler(value = JpaSystemException.class)
    public ResponseEntity<ErrorResponse> handleJpaSystemException(JpaSystemException e) {
        ErrorCode errorCode = ErrorCode.QUERY_FAILED;
        log.error(e.getMessage(), e);
        final ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), "쿼리 요청 오류");
        return new ResponseEntity<>(errorResponse, errorCode.getHttpStatus());
    }

    @ExceptionHandler(value = InvalidDataAccessResourceUsageException.class)
    public ResponseEntity<ErrorResponse> handleInvalidDataAccessResourceUsageException(InvalidDataAccessResourceUsageException e) {
        ErrorCode errorCode = ErrorCode.QUERY_FAILED;
        log.error(e.getMessage(), e);
        final ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), "쿼리 요청 오류");
        return new ResponseEntity<>(errorResponse, errorCode.getHttpStatus());
    }

    @ExceptionHandler(value = SQLSyntaxErrorException.class)
    public ResponseEntity<ErrorResponse> handleSQLSyntaxErrorException(SQLSyntaxErrorException e) {
        ErrorCode errorCode = ErrorCode.QUERY_FAILED;
        log.error(e.getMessage(), e);
        final ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), "쿼리 요청 오류");
        return new ResponseEntity<>(errorResponse, errorCode.getHttpStatus());
    }

    @ExceptionHandler(value = RuntimeException.class)
    public ResponseEntity<ErrorResponse> handleRuntimeException(RuntimeException e) {
        ErrorCode errorCode = ErrorCode.UNEXPECTED_ERROR;
        log.error(e.getMessage(), e);
        final ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), "서버 런타임 오류");
        return new ResponseEntity<>(errorResponse, errorCode.getHttpStatus());
    }
}
