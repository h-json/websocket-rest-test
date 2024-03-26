package com.hjson.websocket_rest_test.service;

import com.hjson.websocket_rest_test.data.dto.*;

public interface AuthService {
    LoginResponseDto login(LoginRequestDto loginRequestDto);
    LogoutResponseDto logout(String email);
    RefreshJwtResponseDto refreshJwt(RefreshJwtRequestDto refreshJwtRequestDto);
    LoginResponseDto loginKakao(String code, String error, String error_description);
    LoginResponseDto loginNaver(String code, String error, String error_description);
    LoginResponseDto loginGoogle(String code, String error, String error_description);
    SocialWithdrawResponseDto withdrawKakao(String email, String code, String error, String error_description);
    SocialWithdrawResponseDto withdrawNaver(String email, String code, String error, String error_description);
    SocialWithdrawResponseDto withdrawGoogle(String email, String code, String error, String error_description);
}
