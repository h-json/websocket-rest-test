package com.hjson.websocket_rest_test.service;

import com.hjson.websocket_rest_test.data.dto.*;
import org.springframework.web.multipart.MultipartFile;

public interface UserService {
    SendCodeResponseDto sendRegisterCode(SendCodeRequestDto sendCodeRequestDto);
    VerifyResponseDto verifyRegisterCode(VerifyCodeRequestDto verifyCodeRequestDto);
    RegisterResponseDto register(RegisterRequestDto registerRequestDto);
    WithdrawResponseDto withdraw(String email);
    VerifyResponseDto verifyPassword(String email, VerifyPasswordRequestDto verifyPasswordRequestDto);
    EditPasswordResponseDto editPassword(String email, EditPasswordRequestDto editPasswordRequestDto);
    SendCodeResponseDto sendResetCode(SendCodeRequestDto sendCodeRequestDto);
    VerifyResponseDto verifyResetCode(VerifyCodeRequestDto verifyCodeRequestDto);
    ResetPasswordResponseDto resetPassword(ResetPasswordRequestDto resetPasswordRequestDto);

}
