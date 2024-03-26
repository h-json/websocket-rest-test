package com.hjson.websocket_rest_test.repository;

import com.hjson.websocket_rest_test.data.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, String> {
    Optional<User> findByEmail(String email);
    Optional<User> findByRefreshToken(String refreshToken);
    List<User> findAllByDeletedAtLessThan(LocalDateTime deleted_at);
}