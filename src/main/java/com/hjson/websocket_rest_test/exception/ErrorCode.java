package com.hjson.websocket_rest_test.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum ErrorCode {
    UNEXPECTED_ERROR("ERROR01", HttpStatus.INTERNAL_SERVER_ERROR, "서버에서 예상하지 못한 오류가 발생한 경우"),
    JSON_PARSE_FAILED("ERROR02", HttpStatus.BAD_REQUEST, "요청의 구조나 자료형이 잘못되어 서버가 이를 해석할 수 없는 경우"),
    QUERY_FAILED("ERROR03", HttpStatus.BAD_REQUEST, "서버가 DB로 쿼리를 보내는 과정에서 PK값이 없거나 범위가 맞지 않아 오류가 발생한 경우"),
    INVALID_FILE_EXTENSION("ERROR04", HttpStatus.BAD_REQUEST, "올바르지 않은 형식의 파일이 전달되어 서버에서 이를 처리할 수 없을 경우"),
    EMAIL_INCORRECT("ERROR05", HttpStatus.UNAUTHORIZED, "아이디가 일치하지 않는 경우"),
    PASSWORD_INCORRECT("ERROR06", HttpStatus.UNAUTHORIZED, "비밀번호가 일치하지 않는 경우"),
    WITHDREW_USER("ERROR07", HttpStatus.UNAUTHORIZED, "이미 탈퇴한 회원이지만, 탈퇴 후 30일이 지나지 않아 DB에 남아있는 경우"),
    AUTHORIZATION_DENIED("ERROR08", HttpStatus.UNAUTHORIZED, "로그인이 되어있지 않거나, JWT가 전송되지 않은 경우"),
    ACCESS_TOKEN_EXPIRED("ERROR09", HttpStatus.UNAUTHORIZED, "액세스 토큰이 만료된 경우"),
    REFRESH_TOKEN_EXPIRED("ERROR10", HttpStatus.UNAUTHORIZED, "리프레시 토큰이 만료된 경우"),
    REFRESH_TOKEN_INCORRECT("ERROR11", HttpStatus.UNAUTHORIZED, "리프레시 토큰이 일치하지 않는 경우"),
    JWT_SIGNATURE_DENIED("ERROR12", HttpStatus.UNAUTHORIZED, "JWT의 서명이 유효하지 않은 경우"),
    UNEXPECTED_JWT_DENIED("ERROR13", HttpStatus.UNAUTHORIZED, "서버에서 예상하지 못한 JWT 오류가 발생한 경우"),
    SOCIAL_DENIED("ERROR14", HttpStatus.UNAUTHORIZED, "SNS와의 연결 과정에서 약관에 동의하지 않고 취소한 경우"),
    SOCIAL_DUPLICATED("ERROR15", HttpStatus.UNAUTHORIZED, "요청한 SNS와 다른 로그인 방식으로 이미 가입된 이메일이 있는 경우"),
    INVALID_SOCIAL_EMAIL("ERROR16", HttpStatus.UNAUTHORIZED, "현재 로그인 되어있는 SNS 계정이 아닌 다른 계정으로 탈퇴를 시도한 경우"),
    UNEXPECTED_SOCIAL_ERROR("ERROR17", HttpStatus.UNAUTHORIZED, "SNS와의 연결 과정에서 예상하지 못한 오류가 발생한 경우"),
    EMAIL_DUPLICATED("ERROR18", HttpStatus.CONFLICT, "이미 존재하는 회원인 경우"),
    REJOIN_DENIED("ERROR19", HttpStatus.CONFLICT, "탈퇴 후 30일이 지나지 않아서 회원 가입이 거절된 경우"),
    CODE_INCORRECT("ERROR20", HttpStatus.UNAUTHORIZED, "인증 코드가 일치하지 않는 경우"),
    NICKNAME_DUPLICATED("ERROR21", HttpStatus.CONFLICT, "같은 활동명을 사용 중인 다른 회원이 있는 경우"),
    SOCIAL_NOT_SUPPORTED("ERROR22", HttpStatus.NOT_FOUND, "소셜 로그인 시 지원하지 않는 기능인 경우"),
    EMAIL_NON_EXISTENT("ERROR23", HttpStatus.UNAUTHORIZED, "존재하지 않는 회원인 경우"),
    INVALID_EMAIL("ERROR24", HttpStatus.BAD_REQUEST, "올바르지 않은 이메일 형식인 경우"),
    INVALID_PASSWORD("ERROR25", HttpStatus.BAD_REQUEST, "올바르지 않은 비밀번호 형식인 경우"),
    FAILED_PASSWORD_VERIFICATION("ERROR26", HttpStatus.BAD_REQUEST, "비밀번호 확인에 실패한 경우");

    private final String code;
    private final HttpStatus httpStatus;
    private final String message;
}
