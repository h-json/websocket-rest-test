package com.hjson.websocket_rest_test.controller;

import com.hjson.websocket_rest_test.data.dto.*;
import com.hjson.websocket_rest_test.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v2/users")
public class UserController {
    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/code")
    public ResponseEntity<SendCodeResponseDto> sendRegisterCode(@RequestBody SendCodeRequestDto sendCodeRequestDto) {
        SendCodeResponseDto sendCodeResponseDto = userService.sendRegisterCode(sendCodeRequestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(sendCodeResponseDto);
    }

    @PostMapping("/code/verify")
    public ResponseEntity<VerifyResponseDto> verifyRegisterCode(@RequestBody VerifyCodeRequestDto verifyCodeRequestDto) {
        VerifyResponseDto verifyResponseDto = userService.verifyRegisterCode(verifyCodeRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(verifyResponseDto);
    }

    @PostMapping(consumes = {MediaType.APPLICATION_JSON_VALUE , MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<RegisterResponseDto> register(@RequestBody RegisterRequestDto registerRequestDto) {
        RegisterResponseDto registerResponseDto = userService.register(registerRequestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(registerResponseDto);
    }

    @DeleteMapping("/me")
    public ResponseEntity<WithdrawResponseDto> withdraw(Authentication authentication) {
        WithdrawResponseDto withdrawResponseDto = userService.withdraw(authentication.getName());

        return ResponseEntity.status(HttpStatus.OK).body(withdrawResponseDto);
    }

    @PostMapping("/me/password/verify")
    public ResponseEntity<VerifyResponseDto> verifyPassword(Authentication authentication, @RequestBody VerifyPasswordRequestDto verifyPasswordRequestDto) {
        VerifyResponseDto verifyResponseDto = userService.verifyPassword(authentication.getName(), verifyPasswordRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(verifyResponseDto);
    }

    @PatchMapping("/me/password")
    public ResponseEntity<EditPasswordResponseDto> editPassword(Authentication authentication, @RequestBody EditPasswordRequestDto editPasswordRequestDto) {
        EditPasswordResponseDto editPasswordResponseDto = userService.editPassword(authentication.getName(), editPasswordRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(editPasswordResponseDto);
    }

    @PostMapping("/me/password/code")
    public ResponseEntity<SendCodeResponseDto> sendResetCode(@RequestBody SendCodeRequestDto sendCodeRequestDto) {
        SendCodeResponseDto sendCodeResponseDto = userService.sendResetCode(sendCodeRequestDto);

        return ResponseEntity.status(HttpStatus.CREATED).body(sendCodeResponseDto);
    }

    @PostMapping("/me/password/code/verify")
    public ResponseEntity<VerifyResponseDto> verifyResetCode(@RequestBody VerifyCodeRequestDto verifyCodeRequestDto) {
        VerifyResponseDto verifyResponseDto = userService.verifyResetCode(verifyCodeRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(verifyResponseDto);
    }

    @PostMapping("/me/password")
    public ResponseEntity<ResetPasswordResponseDto> resetPassword(@RequestBody ResetPasswordRequestDto resetPasswordRequestDto) {
        ResetPasswordResponseDto resetPasswordResponseDto = userService.resetPassword(resetPasswordRequestDto);

        return ResponseEntity.status(HttpStatus.OK).body(resetPasswordResponseDto);
    }
}
