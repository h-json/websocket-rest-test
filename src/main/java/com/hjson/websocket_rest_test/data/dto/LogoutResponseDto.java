package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.domain.Token;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class LogoutResponseDto {
    private String accessToken;
    private String refreshToken;

    public static LogoutResponseDto from(Token token) {
        return new LogoutResponseDto(
                token.getAccessToken(),
                token.getRefreshToken()
        );
    }
}