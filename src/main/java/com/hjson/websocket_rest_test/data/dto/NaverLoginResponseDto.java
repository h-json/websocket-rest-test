package com.hjson.websocket_rest_test.data.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class NaverLoginResponseDto {
    private String access_token;
    private String refresh_token;
    private String token_type;
    private Integer expires_in;
    private String error;
    private String error_description;
}
