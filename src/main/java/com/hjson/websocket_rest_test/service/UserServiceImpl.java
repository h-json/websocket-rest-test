package com.hjson.websocket_rest_test.service;

import com.hjson.websocket_rest_test.data.dto.*;
import com.hjson.websocket_rest_test.data.entity.User;
import com.hjson.websocket_rest_test.exception.GlobalException;
import com.hjson.websocket_rest_test.exception.ErrorCode;
import com.hjson.websocket_rest_test.repository.UserRepository;
import com.hjson.websocket_rest_test.util.EmailAuthUtil;
import com.hjson.websocket_rest_test.util.EmailAuthUtil.Type;
import jakarta.mail.MessagingException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

@Service
public class UserServiceImpl implements UserService {
    private static final Pattern EMAIL_REGEX = Pattern.compile("^[a-zA-Z0-9._\\-]+@[a-zA-Z0-9]+\\.[a-zA-Z]{2,4}$");
    private static final Pattern PASSWORD_REGEX = Pattern.compile("^(?=.*[a-zA-Z])(?=.*\\d)(?=.*[@$!%?&#.~])[A-Za-z\\d@$!%*?&#.~]{8,20}$");
    private static final Pattern NICKNAME_REGEX = Pattern.compile("^[\\da-zA-Zㄱ-힇ぁ-ゔァ-ヴー々〆〤一-龥 ]+$");


    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final EmailAuthUtil emailAuthUtil;

    public UserServiceImpl(
            UserRepository userRepository,
            BCryptPasswordEncoder bCryptPasswordEncoder,
            EmailAuthUtil emailAuthUtil
    ) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.emailAuthUtil = emailAuthUtil;
    }

    @Override
    public SendCodeResponseDto sendRegisterCode(SendCodeRequestDto sendCodeRequestDto) {
        String email = sendCodeRequestDto.getEmail();

        if(!EMAIL_REGEX.matcher(email).find()) {
            throw new GlobalException(ErrorCode.INVALID_EMAIL, "올바른 형식의 이메일이 아닙니다.");
        }

        userRepository.findByEmail(email).ifPresent(u -> {
            if(u.getDeletedAt() != null) {
                throw new GlobalException(ErrorCode.REJOIN_DENIED, "회원 탈퇴 30일 이후 재가입할 수 있습니다.");
            }
            throw new GlobalException(ErrorCode.EMAIL_DUPLICATED, "이미 존재하는 회원입니다.");
        });

        try {
            emailAuthUtil.sendEmail(email, Type.REGISTER);
        } catch (MessagingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new GlobalException(ErrorCode.UNEXPECTED_ERROR, "서버 런타임 오류");
        }

        return new SendCodeResponseDto(email);
    }

    @Override
    public VerifyResponseDto verifyRegisterCode(VerifyCodeRequestDto verifyCodeRequestDto) {
        String email = verifyCodeRequestDto.getEmail();

        if (!EMAIL_REGEX.matcher(email).find()) {
            throw new GlobalException(ErrorCode.INVALID_EMAIL, "올바른 형식의 이메일이 아닙니다.");
        }

        if (!emailAuthUtil.verifyCode(email, verifyCodeRequestDto.getCode(), Type.REGISTER)) {
            throw new GlobalException(ErrorCode.CODE_INCORRECT, "인증코드가 일치하지 않습니다.");
        }

        return new VerifyResponseDto(email);
    }

    @Override
    public RegisterResponseDto register(RegisterRequestDto registerRequestDto) {
        String email = registerRequestDto.getEmail();

        if(!EMAIL_REGEX.matcher(email).find()) {
            throw new GlobalException(ErrorCode.INVALID_EMAIL, "올바른 형식의 이메일이 아닙니다.");
        }

        String password = registerRequestDto.getPassword();

        if(!PASSWORD_REGEX.matcher(password).find()) {
            throw new GlobalException(ErrorCode.INVALID_PASSWORD, "올바른 형식의 비밀번호가 아닙니다.");
        }

        userRepository.findByEmail(email).ifPresent(u -> {
            if(u.getDeletedAt() != null) {
                throw new GlobalException(ErrorCode.REJOIN_DENIED, "회원 탈퇴 30일 이후 재가입할 수 있습니다.");
            }
            throw new GlobalException(ErrorCode.EMAIL_DUPLICATED, "이미 존재하는 회원입니다.");
        });

        if(!emailAuthUtil.verifyCode(email, registerRequestDto.getCode(), Type.REGISTER)) {
            throw new GlobalException(ErrorCode.CODE_INCORRECT, "인증코드가 일치하지 않습니다.");
        }


        User user = registerRequestDto.toUserEntity();
        user.setPassword(bCryptPasswordEncoder.encode(password));

        userRepository.save(user);

        emailAuthUtil.deleteCode(email);

        return new RegisterResponseDto(email);
    }

    @Override
    public WithdrawResponseDto withdraw(String email) {
        if (Objects.equals(email, "")) {
            throw new GlobalException(ErrorCode.AUTHORIZATION_DENIED, "로그인이 필요합니다.");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        user.setRefreshToken(null);
        user.setDeletedAt(LocalDateTime.now());

        userRepository.save(user);

        return new WithdrawResponseDto(email);
    }

    @Override
    public VerifyResponseDto verifyPassword(String email, VerifyPasswordRequestDto verifyPasswordRequestDto) {
        if (Objects.equals(email, "")) {
            throw new GlobalException(ErrorCode.AUTHORIZATION_DENIED, "로그인이 필요합니다.");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() ->
        new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        if(!Objects.equals(user.getProvider(), User.Provider.local)) {
            throw new GlobalException(ErrorCode.SOCIAL_NOT_SUPPORTED, "SNS 로그인 회원의 경우 비밀번호를 설정할 수 없습니다.");
        }

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        if(!bCryptPasswordEncoder.matches(verifyPasswordRequestDto.getPassword(), user.getPassword())) {
            throw new GlobalException(ErrorCode.FAILED_PASSWORD_VERIFICATION, "비밀번호가 틀렸습니다.");
        }

        return new VerifyResponseDto(email);
    }

    @Override
    public EditPasswordResponseDto editPassword(String email, EditPasswordRequestDto editPasswordRequestDto) {
        String password = editPasswordRequestDto.getPassword();

        if(!PASSWORD_REGEX.matcher(password).find()) {
            throw new GlobalException(ErrorCode.INVALID_PASSWORD, "올바른 형식의 비밀번호가 아닙니다.");
        }

        if (Objects.equals(email, "")) {
            throw new GlobalException(ErrorCode.AUTHORIZATION_DENIED, "로그인이 필요합니다.");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        if(!Objects.equals(user.getProvider(), User.Provider.local)) {
            throw new GlobalException(ErrorCode.SOCIAL_NOT_SUPPORTED, "SNS 로그인 회원의 경우 비밀번호를 설정할 수 없습니다.");
        }

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        return new EditPasswordResponseDto(email);
    }

    @Override
    public SendCodeResponseDto sendResetCode(SendCodeRequestDto sendCodeRequestDto) {
        String email = sendCodeRequestDto.getEmail();

        if(!EMAIL_REGEX.matcher(email).find()) {
            throw new GlobalException(ErrorCode.INVALID_EMAIL, "올바른 형식의 이메일이 아닙니다.");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() ->
            new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        if(!Objects.equals(user.getProvider(), User.Provider.local)) {
            throw new GlobalException(ErrorCode.SOCIAL_NOT_SUPPORTED, "SNS 로그인 회원의 경우 비밀번호를 설정할 수 없습니다.");
        }

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        try {
            emailAuthUtil.sendEmail(email, Type.RESET);
        } catch (MessagingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new GlobalException(ErrorCode.UNEXPECTED_ERROR, "서버 런타임 오류");
        }

        return new SendCodeResponseDto(email);
    }

    @Override
    public VerifyResponseDto verifyResetCode(VerifyCodeRequestDto verifyCodeRequestDto) {
        String email = verifyCodeRequestDto.getEmail();

        if(!EMAIL_REGEX.matcher(email).find()) {
            throw new GlobalException(ErrorCode.INVALID_EMAIL, "올바른 형식의 이메일이 아닙니다.");
        }

        if(!emailAuthUtil.verifyCode(email, verifyCodeRequestDto.getCode(), Type.RESET)) {
            throw new GlobalException(ErrorCode.CODE_INCORRECT, "인증코드가 일치하지 않습니다.");
        }

        return new VerifyResponseDto(email);
    }

    @Override
    public ResetPasswordResponseDto resetPassword(ResetPasswordRequestDto resetPasswordRequestDto) {
        String email = resetPasswordRequestDto.getEmail();

        if(!EMAIL_REGEX.matcher(email).find()) {
            throw new GlobalException(ErrorCode.INVALID_EMAIL, "올바른 형식의 이메일이 아닙니다.");
        }

        String password = resetPasswordRequestDto.getPassword();

        if(!PASSWORD_REGEX.matcher(password).find()) {
            throw new GlobalException(ErrorCode.INVALID_PASSWORD, "올바른 형식의 비밀번호가 아닙니다.");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        if(!Objects.equals(user.getProvider(), User.Provider.local)) {
            throw new GlobalException(ErrorCode.SOCIAL_NOT_SUPPORTED, "SNS 로그인 회원의 경우 비밀번호를 설정할 수 없습니다.");
        }

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        if(!emailAuthUtil.verifyCode(email, resetPasswordRequestDto.getCode(), Type.RESET)) {
            throw new GlobalException(ErrorCode.CODE_INCORRECT, "인증코드가 일치하지 않습니다.");
        }

        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);

        emailAuthUtil.deleteCode(email);

        return new ResetPasswordResponseDto(email);
    }
}
