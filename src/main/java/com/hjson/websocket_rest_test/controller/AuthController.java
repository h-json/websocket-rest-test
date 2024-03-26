package com.hjson.websocket_rest_test.controller;

import com.hjson.websocket_rest_test.data.dto.*;
import com.hjson.websocket_rest_test.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v2/auth")
public class AuthController {
    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/token")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequestDto) {
        LoginResponseDto loginResponseDto = authService.login(loginRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(loginResponseDto);
    }

    @DeleteMapping("/token")
    public ResponseEntity<LogoutResponseDto> logout(Authentication authentication) {
        LogoutResponseDto logoutResponseDto = authService.logout(authentication.getName());

        return ResponseEntity.status(HttpStatus.OK).body(logoutResponseDto);
    }

    @PatchMapping("/token")
    public ResponseEntity<RefreshJwtResponseDto> refreshJwt(@RequestBody RefreshJwtRequestDto refreshJwtRequestDto) {
        RefreshJwtResponseDto refreshJwtResponseDto = authService.refreshJwt(refreshJwtRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(refreshJwtResponseDto);
    }

    @GetMapping("/kakao")
    public ResponseEntity<LoginResponseDto> loginKakao(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description
    ) {
        LoginResponseDto loginResponseDto = authService.loginKakao(code, error, error_description);

        return ResponseEntity.status(HttpStatus.OK).body(loginResponseDto);
    }

    @GetMapping("/naver")
    public ResponseEntity<LoginResponseDto> loginNaver(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description
    ) {
        LoginResponseDto loginResponseDto = authService.loginNaver(code, error, error_description);

        return ResponseEntity.status(HttpStatus.OK).body(loginResponseDto);
    }

    @GetMapping("/google")
    public ResponseEntity<LoginResponseDto> loginGoogle(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description
    ) {
        LoginResponseDto loginResponseDto = authService.loginGoogle(code, error, error_description);

        return ResponseEntity.status(HttpStatus.OK).body(loginResponseDto);
    }

    @DeleteMapping("/kakao")
    public ResponseEntity<SocialWithdrawResponseDto> withdrawKakao(
            Authentication authentication,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description
    ) {
        SocialWithdrawResponseDto socialWithdrawResponseDto = authService.withdrawKakao(authentication.getName(), code, error, error_description);

        return ResponseEntity.status(HttpStatus.OK).body(socialWithdrawResponseDto);
    }

    @DeleteMapping("/naver")
    public ResponseEntity<SocialWithdrawResponseDto> withdrawNaver(
            Authentication authentication,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description
    ) {
        SocialWithdrawResponseDto socialWithdrawResponseDto = authService.withdrawNaver(authentication.getName(), code, error, error_description);

        return ResponseEntity.status(HttpStatus.OK).body(socialWithdrawResponseDto);
    }

    @DeleteMapping("/google")
    public ResponseEntity<SocialWithdrawResponseDto> withdrawGoogle(
            Authentication authentication,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description
    ) {
        SocialWithdrawResponseDto socialWithdrawResponseDto = authService.withdrawGoogle(authentication.getName(), code, error, error_description);

        return ResponseEntity.status(HttpStatus.OK).body(socialWithdrawResponseDto);
    }
}
