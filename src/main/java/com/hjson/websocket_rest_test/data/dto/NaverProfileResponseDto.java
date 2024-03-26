package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.entity.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.Objects;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class NaverProfileResponseDto {
    private String resultcode;
    private String message;
    private NaverProfileResponseDtoElement response;

    public User toUserEntity() {
        return new User(
                response.getEmail(),
                null,
                null,
                User.Provider.naver,
                LocalDateTime.now(),
                LocalDateTime.now(),
                null
        );
    }
}
