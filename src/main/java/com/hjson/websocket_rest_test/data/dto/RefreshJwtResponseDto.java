package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.domain.Token;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class RefreshJwtResponseDto {
    private String accessToken;
    private String refreshToken;

    public static RefreshJwtResponseDto from(Token token) {
        return new RefreshJwtResponseDto(
                token.getAccessToken(),
                token.getRefreshToken()
        );
    }
}