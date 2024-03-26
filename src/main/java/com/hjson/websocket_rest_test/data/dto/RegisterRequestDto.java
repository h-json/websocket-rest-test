package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.entity.User;
import com.hjson.websocket_rest_test.data.entity.User.Provider;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class RegisterRequestDto {
    private String email;
    private String code;
    private String password;

    public User toUserEntity() {
        return new User(
                getEmail(),
                null,
                null,
                Provider.local,
                LocalDateTime.now(),
                LocalDateTime.now(),
                null
        );
    }
}
