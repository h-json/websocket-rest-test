package com.hjson.websocket_rest_test.data.dto;

import lombok.*;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
public class NaverWithdrawResponseDto {
    private String access_token;
    private String result;
}
