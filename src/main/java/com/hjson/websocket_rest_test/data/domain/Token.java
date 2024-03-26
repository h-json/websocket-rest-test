package com.hjson.websocket_rest_test.data.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class Token {
    private String accessToken;
    private String refreshToken;
}
