package com.hjson.websocket_rest_test.data.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class VerifyCodeRequestDto {
    private String email;
    private String code;
}
