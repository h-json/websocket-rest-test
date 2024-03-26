package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class SocialWithdrawResponseDto {
    private String email;
    private String provider;

    public static SocialWithdrawResponseDto from(User user) {
        return new SocialWithdrawResponseDto(
                user.getEmail(),
                user.getProvider().toString()
        );
    }
}
