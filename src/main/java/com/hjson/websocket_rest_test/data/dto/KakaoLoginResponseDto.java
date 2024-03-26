package com.hjson.websocket_rest_test.data.dto;

import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class KakaoLoginResponseDto {
    private String token_type;
    private String access_token;
    private String refresh_token;
    private Integer expires_in;
    private Integer refresh_token_expires_in;
}
