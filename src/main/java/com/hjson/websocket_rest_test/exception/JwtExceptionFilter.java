package com.hjson.websocket_rest_test.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hjson.websocket_rest_test.data.dto.ErrorResponse;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtExceptionFilter extends OncePerRequestFilter {
    Logger log = LoggerFactory.getLogger(this.getClass());

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            handleJwtException(response, ErrorCode.ACCESS_TOKEN_EXPIRED, "액세스 토큰이 만료되었습니다.");
        } catch (SignatureException e) {
            log.error(e.getMessage(), e);
            handleJwtException(response, ErrorCode.JWT_SIGNATURE_DENIED, "올바르지 않은 서명의 토큰입니다.");
        } catch (GlobalException e) {
            handleJwtException(response, e.getErrorCode(), e.getMessage());
        } catch (JwtException e) {
            log.error(e.getMessage(), e);
            handleJwtException(response, ErrorCode.UNEXPECTED_JWT_DENIED, "알 수 없는 토큰 오류입니다.");
        }
    }

    private void handleJwtException(HttpServletResponse response, ErrorCode errorCode, String message) {
        ObjectMapper objectMapper = new ObjectMapper();

        response.setStatus(errorCode.getHttpStatus().value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        ErrorResponse errorResponse = new ErrorResponse(errorCode.getCode(), errorCode.getHttpStatus().toString(), message);

        try {
            response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
