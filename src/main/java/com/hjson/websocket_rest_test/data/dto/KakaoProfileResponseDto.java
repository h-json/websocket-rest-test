package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class KakaoProfileResponseDto {
    private String id;
    private LocalDateTime connected_at;
    private LocalDateTime synched_at;
    private KakaoProfileResponseDtoElement kakao_account;

    public User toUserEntity() {
        return new User(
                kakao_account.getEmail(),
                null,
                null,
                User.Provider.kakao,
                LocalDateTime.now(),
                LocalDateTime.now(),
                null
        );
    }
}
