package com.hjson.websocket_rest_test.data.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class User {
    @Id
    @Column(length = 100, nullable = false)
    public String email;

    public String password;

    @Column(length = 300)
    public String refreshToken;

    @Enumerated(EnumType.STRING)
    public Provider provider;

    @Column(nullable = false)
    public LocalDateTime createdAt;

    @Column(nullable = false)
    public LocalDateTime updatedAt;

    public LocalDateTime deletedAt;

    public enum Provider {
        local, kakao, naver, google
    }
}