package com.hjson.websocket_rest_test.service;

import com.hjson.websocket_rest_test.data.domain.Token;
import com.hjson.websocket_rest_test.data.dto.*;
import com.hjson.websocket_rest_test.data.entity.User;
import com.hjson.websocket_rest_test.exception.GlobalException;
import com.hjson.websocket_rest_test.exception.ErrorCode;
import com.hjson.websocket_rest_test.repository.UserRepository;
import com.hjson.websocket_rest_test.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;

@Service
public class AuthServiceImpl implements AuthService {
    Logger log = LoggerFactory.getLogger(this.getClass());

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Value("${jwt.secret.access}")
    private String accessSecretKey;
    @Value("${jwt.secret.refresh}")
    private String refreshSecretKey;

    @Value("${server.domain}")
    private String domain;
    @Value("${social.kakao.client-id}")
    private String kakaoId;
    @Value("${social.kakao.client-secret}")
    private String kakaoSecret;
    @Value("${social.naver.client-id}")
    private String naverId;
    @Value("${social.naver.client-secret}")
    private String naverSecret;
    @Value("${social.google.client-id}")
    private String googleId;
    @Value("${social.google.client-secret}")
    private String googleSecret;

    public AuthServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public LoginResponseDto login(LoginRequestDto loginRequestDto) {
        String email = loginRequestDto.getEmail();
        String password = loginRequestDto.getPassword();

        // 스프링 시큐리티 제대로 공부해서 꼭 시큐리티 기능 이용해서 다시 구현해보자...
        User user = userRepository.findByEmail(email).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_INCORRECT, "아이디 또는 비밀번호가 틀렸습니다.")
        );

        if(!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new GlobalException(ErrorCode.PASSWORD_INCORRECT, "아이디 또는 비밀번호가 틀렸습니다.");
        }

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        Token token = JwtUtil.createToken(email, user.getProvider(), accessSecretKey, refreshSecretKey);

        user.setRefreshToken(token.getRefreshToken());
        userRepository.save(user);

        return LoginResponseDto.from(token);
    }

    @Override
    public LogoutResponseDto logout(String email) {
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
        userRepository.save(user);

        Token token = JwtUtil.deleteToken();

        return LogoutResponseDto.from(token);
    }

    @Override
    public RefreshJwtResponseDto refreshJwt(RefreshJwtRequestDto refreshJwtRequestDto) {
        String oldAccessToken = refreshJwtRequestDto.getAccessToken();
        String oldRefreshToken = refreshJwtRequestDto.getRefreshToken();

        String email = "";
        // 받은 액세스 토큰과 리프레시 토큰의 유효성 검사 --------
        try {
            JwtUtil.isExpired(oldAccessToken, accessSecretKey);
        } catch (SignatureException e) {
            throw new GlobalException(ErrorCode.JWT_SIGNATURE_DENIED, "올바르지 않은 서명의 토큰입니다.");
        } catch (ExpiredJwtException ignored) {

        } catch (JwtException e) {
            throw new GlobalException(ErrorCode.UNEXPECTED_JWT_DENIED, "알 수 없는 토큰 오류입니다.");
        }

        try {
            email = JwtUtil.getEmail(oldRefreshToken, refreshSecretKey);
        } catch (SignatureException e) {
            throw new GlobalException(ErrorCode.JWT_SIGNATURE_DENIED, "올바르지 않은 서명의 토큰입니다.");
        } catch (ExpiredJwtException e) {
            throw new GlobalException(ErrorCode.REFRESH_TOKEN_EXPIRED, "리프레시 토큰이 만료되었습니다.");
        } catch (JwtException e) {
            throw new GlobalException(ErrorCode.UNEXPECTED_JWT_DENIED, "알 수 없는 토큰 오류입니다.");
        }

        User user = userRepository.findByEmail(email).orElseThrow(() ->
                new GlobalException(ErrorCode.REFRESH_TOKEN_INCORRECT, "유효하지 않은 리프레시 토큰입니다.")
        );

        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        // -----------------------------------------------

        // 리프레시 토큰이 유효하면 액세스 토큰 재발급
        String newAccessToken = JwtUtil.createAccessToken(user.getEmail(), user.getProvider(), accessSecretKey);

        // 리프래시 토큰의 유효기간이 얼마 남지 않았으면 리프레시 토큰도 재발급 -------
        String newRefreshToken = oldRefreshToken;

        if(JwtUtil.canRefreshRefreshToken(oldRefreshToken, refreshSecretKey)) {
            newRefreshToken = JwtUtil.createRefreshToken(email, refreshSecretKey);

            user.setRefreshToken(newRefreshToken);
            userRepository.save(user);
        }
        // ----------------------------------------------------------------

        Token token = new Token(newAccessToken, newRefreshToken);

        return RefreshJwtResponseDto.from(token);
    }

    @Override
    public LoginResponseDto loginKakao(String code, String error, String error_description) {
        // 사용자 동의 확인
        if(error != null) {
            log.error("error: {}\nerror_description: {}", error, error_description);
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 인증 코드 이용하여 카카오에 로그인 및 액세스 토큰 요청
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", kakaoId);
        body.add("client_secret", kakaoSecret);
        body.add("redirect_uri", domain + "/login/kakao");
        body.add("code", code);

        WebClient webClient = WebClient.builder().baseUrl("https://kauth.kakao.com").build();
        KakaoLoginResponseDto loginResponse = webClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/oauth/token").build())
                .headers(headers -> headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8"))
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(KakaoLoginResponseDto.class)
                .block();

        if(loginResponse == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String accessToken = loginResponse.getAccess_token();

        // 액세스 토큰 이용하여 카카오에 로그인한 계정 정보 가져오기
        WebClient profileWebClient = WebClient.builder().baseUrl("https://kapi.kakao.com").build();
        KakaoProfileResponseDto profileResponse = profileWebClient
                .get()
                .uri(uriBuilder -> uriBuilder.path("/v2/user/me").build())
                .headers(headers -> {
                    headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
                    headers.add("Authorization", "Bearer " + accessToken);
                })
                .retrieve()
                .bodyToMono(KakaoProfileResponseDto.class)
                .block();

        if(profileResponse == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 브로콜리 가입 여부 확인
        userRepository.findByEmail(profileResponse.getKakao_account().getEmail()).ifPresentOrElse(
                user -> { // 브로콜리에 가입되어 있다면
                    if (!Objects.equals(user.getProvider(), User.Provider.kakao)) { // 다른 소셜에서 가입된 이메일인지 확인
                        KakaoWithdrawResponseDto withdrawResponse = profileWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder.path("/v1/user/unlink").build())
                                .headers(headers -> {
                                    headers.add("Authorization", "Bearer " + accessToken);
                                })
                                .retrieve()
                                .bodyToMono(KakaoWithdrawResponseDto.class)
                                .block();

                        if (withdrawResponse == null || withdrawResponse.getId() == null) {
                            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                        }

                        throw new GlobalException(ErrorCode.SOCIAL_DUPLICATED, "이미 다른 로그인 방식으로 가입한 계정이 있습니다.");
                    } else if (user.getDeletedAt() != null) { // 탈퇴한 회원인지 확인
                        KakaoWithdrawResponseDto withdrawResponse = profileWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder.path("/v1/user/unlink").build())
                                .headers(headers -> {
                                    headers.add("Authorization", "Bearer " + accessToken);
                                })
                                .retrieve()
                                .bodyToMono(KakaoWithdrawResponseDto.class)
                                .block();

                        if (withdrawResponse == null || withdrawResponse.getId() == null) {
                            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                        }

                        throw new GlobalException(ErrorCode.REJOIN_DENIED, "회원 탈퇴 30일 이후 재가입할 수 있습니다.");
                    }
                },
                () -> { // 아직 가입되어 있지 않다면 브로콜리 가입 처리
                    User user = profileResponse.toUserEntity();
                    userRepository.save(user);
                }
        );

        // 사용자 정보 갱신
        User user = userRepository.findByEmail(profileResponse.getKakao_account().getEmail()).orElseThrow(() ->
                new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.")
        );

        User nowUser = profileResponse.toUserEntity();

        // 로그인 처리
        Token token = JwtUtil.createToken(user.getEmail(), user.getProvider(), accessSecretKey, refreshSecretKey);

        user.setRefreshToken(token.getRefreshToken());
        userRepository.save(user);

        // 모든 작업 후 카카오 액세스 토큰 만료 처리 (카카오 로그아웃)
        KakaoLogoutResponseDto logoutResponse = profileWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/v1/user/logout").build())
                .headers(headers -> {
                    headers.add("Authorization", "Bearer " + accessToken);
                })
                .retrieve()
                .bodyToMono(KakaoLogoutResponseDto.class)
                .block();

        if (logoutResponse == null || logoutResponse.getId() == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        return LoginResponseDto.from(token);
    }

    @Override
    public LoginResponseDto loginNaver(String code, String error, String error_description) {
        // 사용자 동의 확인
        if(error != null) {
            log.error("error: {}\nerror_description: {}", error, error_description);
            if(Objects.equals(error, "access_denied")) {
                throw new GlobalException(ErrorCode.SOCIAL_DENIED, "SNS와의 연결을 거부하였습니다.");
            }
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 인증 코드 이용하여 네이버에 로그인 및 액세스 토큰 요청
        String state = getRandomState();

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", naverId);
        body.add("client_secret", naverSecret);
        body.add("code", code);
        body.add("state", state);

        WebClient loginWebClient = WebClient.builder().baseUrl("https://nid.naver.com").build();
        NaverLoginResponseDto loginResponse = loginWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/oauth2.0/token").build())
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(NaverLoginResponseDto.class)
                .block();

        if(loginResponse == null || loginResponse.getError() != null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String accessToken = loginResponse.getAccess_token();

        // 액세스 토큰 이용하여 네이버에 로그인한 계정 정보 가져오기
        WebClient profileWebClient = WebClient.builder().baseUrl("https://openapi.naver.com").build();
        NaverProfileResponseDto profileResponse = profileWebClient
                .get()
                .uri(uriBuilder -> uriBuilder.path("/v1/nid/me").build())
                .headers(headers -> headers.add("Authorization","Bearer " + accessToken))
                .retrieve()
                .bodyToMono(NaverProfileResponseDto.class)
                .block();

        if(profileResponse == null || !Objects.equals(profileResponse.getResultcode(), "00")) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 브로콜리 가입 여부 확인
        userRepository.findByEmail(profileResponse.getResponse().getEmail()).ifPresentOrElse(
                user -> { // 브로콜리에 가입되어 있다면
                    if (!Objects.equals(user.getProvider(), User.Provider.naver)) { // 다른 소셜에서 가입된 이메일인지 확인
                        body.remove("code");
                        body.remove("state");
                        body.set("grant_type", "delete");
                        body.add("access_token", accessToken);
                        body.add("service_provider", "NAVER");

                        NaverWithdrawResponseDto withdrawResponse = loginWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder.path("/oauth2.0/token").build())
                                .body(BodyInserters.fromFormData(body))
                                .retrieve()
                                .bodyToMono(NaverWithdrawResponseDto.class)
                                .block();

                        if (withdrawResponse == null || !Objects.equals(withdrawResponse.getResult(), "success")) {
                            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                        }

                        throw new GlobalException(ErrorCode.SOCIAL_DUPLICATED, "이미 다른 로그인 방식으로 가입한 계정이 있습니다.");
                    } else if (user.getDeletedAt() != null) { // 탈퇴한 회원인지 확인
                        body.remove("code");
                        body.remove("state");
                        body.set("grant_type", "delete");
                        body.add("access_token", accessToken);
                        body.add("service_provider", "NAVER");

                        NaverWithdrawResponseDto withdrawResponse = loginWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder.path("/oauth2.0/token").build())
                                .body(BodyInserters.fromFormData(body))
                                .retrieve()
                                .bodyToMono(NaverWithdrawResponseDto.class)
                                .block();

                        if (withdrawResponse == null || !Objects.equals(withdrawResponse.getResult(), "success")) {
                            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                        }

                        throw new GlobalException(ErrorCode.REJOIN_DENIED, "회원 탈퇴 30일 이후 재가입할 수 있습니다.");
                    }
                },
                () -> { // 아직 가입되어 있지 않다면 브로콜리 가입 처리
                    User user = profileResponse.toUserEntity();
                    userRepository.save(user);
                }
        );

        // 사용자 정보 갱신
        User user = userRepository.findByEmail(profileResponse.getResponse().getEmail()).orElseThrow(() ->
                new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.")
        );

        User nowUser = profileResponse.toUserEntity();

        // 로그인 처리
        Token token = JwtUtil.createToken(user.getEmail(), user.getProvider(), accessSecretKey, refreshSecretKey);

        user.setRefreshToken(token.getRefreshToken());
        userRepository.save(user);

        return LoginResponseDto.from(token);
    }

    private String getRandomState() {
        SecureRandom random = new SecureRandom();

        return random.ints(48, 123)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(32)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    @Override
    public LoginResponseDto loginGoogle(String code, String error, String error_description) {
        // 사용자 동의 확인
        if(error != null) {
            log.error("error: {}\nerror_description: {}", error, error_description);
            if(Objects.equals(error, "access_denied")) {
                throw new GlobalException(ErrorCode.SOCIAL_DENIED, "SNS와의 연결을 거부하였습니다.");
            }
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 인증 코드 이용하여 구글에 로그인 및 액세스 토큰 요청
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", googleId);
        body.add("client_secret", googleSecret);
        body.add("code", code);
        body.add("redirect_uri", domain + "/login/google");

        WebClient loginWebClient = WebClient.builder().baseUrl("https://oauth2.googleapis.com").build();
        GoogleLoginResponseDto loginResponse = loginWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/token").build())
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(GoogleLoginResponseDto.class)
                .block();

        if(loginResponse == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String accessToken = loginResponse.getAccess_token();

        // 액세스 토큰 이용하여 구글에 로그인한 계정 정보 가져오기
        MultiValueMap<String, String> param = new LinkedMultiValueMap<>();
        param.add("personFields", "emailAddresses,genders,birthdays");

        WebClient profileWebClient = WebClient.builder().baseUrl("https://people.googleapis.com").build();
        GoogleProfileResponseDto profileResponse = profileWebClient
                .get()
                .uri(uriBuilder -> uriBuilder
                        .path("/v1/people/me")
                        .queryParams(param)
                        .build())

                .headers(headers -> {
                    headers.add("Authorization","Bearer " + accessToken);
                })
                .retrieve()
                .bodyToMono(GoogleProfileResponseDto.class)
                .block();

        if(profileResponse == null || profileResponse.getEmailAddresses() == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 브로콜리 가입 여부 확인
        userRepository.findByEmail(profileResponse.getEmailAddresses().get(0).getValue()).ifPresentOrElse(
                user -> { // 브로콜리에 가입되어 있다면
                    if (!Objects.equals(user.getProvider(), User.Provider.google)) { // 다른 소셜에서 가입된 이메일인지 확인
                        loginWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder
                                        .path("/revoke")
                                        .queryParam("token", accessToken)
                                        .build())
                                .headers(headers -> headers.add("Content-type", "application/x-www-form-urlencoded"))
                                .exchangeToMono(response -> response.bodyToMono(Map.class).map(map -> {
                                    if(response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                                        throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                                    }

                                    return map;
                                }))
                                .block();

                        throw new GlobalException(ErrorCode.SOCIAL_DUPLICATED, "이미 다른 로그인 방식으로 가입한 계정이 있습니다.");
                    } else if (user.getDeletedAt() != null) { // 탈퇴한 회원인지 확인
                        loginWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder
                                        .path("/revoke")
                                        .queryParam("token", accessToken)
                                        .build())
                                .headers(headers -> headers.add("Content-type", "application/x-www-form-urlencoded"))
                                .exchangeToMono(response -> response.bodyToMono(Map.class).map(map -> {
                                    if(response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                                        throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                                    }

                                    return map;
                                }))
                                .block();

                        throw new GlobalException(ErrorCode.REJOIN_DENIED, "회원 탈퇴 30일 이후 재가입할 수 있습니다.");
                    }
                },
                () -> { // 아직 가입되어 있지 않다면 브로콜리 가입 처리
                    User user = profileResponse.toUserEntity();
                    userRepository.save(user);
                }
        );

        // 사용자 정보 갱신
        User user = userRepository.findByEmail(profileResponse.getEmailAddresses().get(0).getValue()).orElseThrow(() ->
                new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.")
        );

        User nowUser = profileResponse.toUserEntity();

        // 로그인 처리
        Token token = JwtUtil.createToken(user.getEmail(), user.getProvider(), accessSecretKey, refreshSecretKey);

        user.setRefreshToken(token.getRefreshToken());
        userRepository.save(user);

        return LoginResponseDto.from(token);
    }

    @Override
    public SocialWithdrawResponseDto withdrawKakao(String tokenEmail, String code, String error, String error_description) {
        // 사용자 동의 확인
        if(error != null) {
            log.error("error: {}\nerror_description: {}", error, error_description);
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 인증 코드 이용하여 카카오에 로그인 및 액세스 토큰 요청
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", kakaoId);
        body.add("client_secret", kakaoSecret);
        body.add("redirect_uri", domain + "/withdraw/kakao");
        body.add("code", code);

        WebClient webClient = WebClient.builder().baseUrl("https://kauth.kakao.com").build();
        KakaoLoginResponseDto loginResponse = webClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/oauth/token").build())
                .headers(headers -> headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8"))
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(KakaoLoginResponseDto.class)
                .block();

        if(loginResponse == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String accessToken = loginResponse.getAccess_token();

        // 액세스 토큰 이용하여 카카오에 로그인한 계정 정보 가져오기
        WebClient profileWebClient = WebClient.builder().baseUrl("https://kapi.kakao.com").build();
        KakaoProfileResponseDto profileResponse = profileWebClient
                .get()
                .uri(uriBuilder -> uriBuilder.path("/v2/user/me").build())
                .headers(headers -> {
                    headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");
                    headers.add("Authorization", "Bearer " + accessToken);
                })
                .retrieve()
                .bodyToMono(KakaoProfileResponseDto.class)
                .block();

        if(profileResponse == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String socialEmail = profileResponse.getKakao_account().getEmail();

        // 현재 로그인 되어있는 SNS 계정이 아닌 다른 계정으로 탈퇴를 시도했다면 예외 발생
        if(!Objects.equals(tokenEmail, socialEmail)) {
            userRepository.findByEmail(socialEmail).ifPresentOrElse(
                    // 다른 계정이 브로콜리에 가입된 계정이라면
                    user -> {
                        // 탈퇴 시키지 않고 예외 처리
                        throw new GlobalException(ErrorCode.INVALID_SOCIAL_EMAIL, "현재 로그인한 SNS 계정과 다른 계정입니다.");
                    },
                    // 소셜 계정이 브로콜리에 없는 계정이라면
                    () -> {
                        // SNS와의 연동 끊기
                        KakaoWithdrawResponseDto withdrawResponse = profileWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder.path("/v1/user/unlink").build())
                                .headers(headers -> {
                                    headers.add("Authorization", "Bearer " + accessToken);
                                })
                                .retrieve()
                                .bodyToMono(KakaoWithdrawResponseDto.class)
                                .block();

                        throw new GlobalException(ErrorCode.INVALID_SOCIAL_EMAIL, "현재 로그인한 SNS 계정과 다른 계정입니다.");
                    }
            );
        }

        // SNS와의 연동 끊기
        KakaoWithdrawResponseDto withdrawResponse = profileWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/v1/user/unlink").build())
                .headers(headers -> {
                    headers.add("Authorization", "Bearer " + accessToken);
                })
                .retrieve()
                .bodyToMono(KakaoWithdrawResponseDto.class)
                .block();

        if (withdrawResponse == null || withdrawResponse.getId() == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 없는 회원이면 예외 발생
        User user = userRepository.findByEmail(socialEmail).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        // 이미 탈퇴한 회원이라면 예외 발생
        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        // 정상적인 접근이면 탈퇴 처리
        user.setRefreshToken(null);
        user.setDeletedAt(LocalDateTime.now());

        userRepository.save(user);

        return SocialWithdrawResponseDto.from(user);
    }

    @Override
    public SocialWithdrawResponseDto withdrawNaver(String tokenEmail, String code, String error, String error_description) {
        // 사용자 동의 확인
        if(error != null) {
            log.error("error: {}\nerror_description: {}", error, error_description);
            if(Objects.equals(error, "access_denied")) {
                throw new GlobalException(ErrorCode.SOCIAL_DENIED, "SNS와의 연결을 거부하였습니다.");
            }
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 인증 코드 이용하여 네이버에 로그인 및 액세스 토큰 요청
        String state = getRandomState();

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", naverId);
        body.add("client_secret", naverSecret);
        body.add("code", code);
        body.add("state", state);

        WebClient loginWebClient = WebClient.builder().baseUrl("https://nid.naver.com").build();
        NaverLoginResponseDto loginResponse = loginWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/oauth2.0/token").build())
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(NaverLoginResponseDto.class)
                .block();

        if(loginResponse == null || loginResponse.getError() != null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String accessToken = loginResponse.getAccess_token();

        // 액세스 토큰 이용하여 네이버에 로그인한 계정 정보 가져오기
        WebClient profileWebClient = WebClient.builder().baseUrl("https://openapi.naver.com").build();
        NaverProfileResponseDto profileResponse = profileWebClient
                .get()
                .uri(uriBuilder -> uriBuilder.path("/v1/nid/me").build())
                .headers(headers -> headers.add("Authorization","Bearer " + accessToken))
                .retrieve()
                .bodyToMono(NaverProfileResponseDto.class)
                .block();

        if(profileResponse == null || !Objects.equals(profileResponse.getResultcode(), "00")) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String socialEmail = profileResponse.getResponse().getEmail();

        // 소셜 탈퇴 요청 준비
        body.remove("code");
        body.remove("state");
        body.set("grant_type", "delete");
        body.add("access_token", accessToken);
        body.add("service_provider", "NAVER");

        // 현재 로그인 되어있는 SNS 계정이 아닌 다른 계정으로 탈퇴를 시도했다면 예외 발생
        if(!Objects.equals(tokenEmail, socialEmail)) {
            userRepository.findByEmail(socialEmail).ifPresentOrElse(
                    // 다른 계정이 브로콜리에 가입된 계정이라면
                    user -> {
                        // 탈퇴 시키지 않고 예외 처리
                        throw new GlobalException(ErrorCode.INVALID_SOCIAL_EMAIL, "현재 로그인한 SNS 계정과 다른 계정입니다.");
                    },
                    // 소셜 계정이 브로콜리에 없는 계정이라면
                    () -> {
                        // SNS와의 연동 끊기
                        NaverWithdrawResponseDto withdrawResponse = loginWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder.path("/oauth2.0/token").build())
                                .body(BodyInserters.fromFormData(body))
                                .retrieve()
                                .bodyToMono(NaverWithdrawResponseDto.class)
                                .block();

                        throw new GlobalException(ErrorCode.INVALID_SOCIAL_EMAIL, "현재 로그인한 SNS 계정과 다른 계정입니다.");
                    }
            );
        }

        // SNS와의 연동 끊기
        NaverWithdrawResponseDto withdrawResponse = loginWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/oauth2.0/token").build())
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(NaverWithdrawResponseDto.class)
                .block();

        if (withdrawResponse == null || !Objects.equals(withdrawResponse.getResult(), "success")) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 없는 회원이면 예외 발생
        User user = userRepository.findByEmail(socialEmail).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        // 이미 탈퇴한 회원이라면 예외 발생
        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        // 정상적인 접근이면 탈퇴 처리
        user.setRefreshToken(null);
        user.setDeletedAt(LocalDateTime.now());

        userRepository.save(user);

        return SocialWithdrawResponseDto.from(user);
    }

    @Override
    public SocialWithdrawResponseDto withdrawGoogle(String tokenEmail, String code, String error, String error_description) {
        // 사용자 동의 확인
        if(error != null) {
            log.error("error: {}\nerror_description: {}", error, error_description);
            if(Objects.equals(error, "access_denied")) {
                throw new GlobalException(ErrorCode.SOCIAL_DENIED, "SNS와의 연결을 거부하였습니다.");
            }
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        // 인증 코드 이용하여 구글에 로그인 및 액세스 토큰 요청
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", googleId);
        body.add("client_secret", googleSecret);
        body.add("code", code);
        body.add("redirect_uri", domain + "/withdraw/google");

        WebClient loginWebClient = WebClient.builder().baseUrl("https://oauth2.googleapis.com").build();
        GoogleLoginResponseDto loginResponse = loginWebClient
                .post()
                .uri(uriBuilder -> uriBuilder.path("/token").build())
                .body(BodyInserters.fromFormData(body))
                .retrieve()
                .bodyToMono(GoogleLoginResponseDto.class)
                .block();

        if(loginResponse == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String accessToken = loginResponse.getAccess_token();

        // 액세스 토큰 이용하여 구글에 로그인한 계정 정보 가져오기
        MultiValueMap<String, String> param = new LinkedMultiValueMap<>();
        param.add("personFields", "emailAddresses");

        WebClient profileWebClient = WebClient.builder().baseUrl("https://people.googleapis.com").build();
        GoogleProfileResponseDto profileResponse = profileWebClient
                .get()
                .uri(uriBuilder -> uriBuilder
                        .path("/v1/people/me")
                        .queryParams(param)
                        .build())

                .headers(headers -> {
                    headers.add("Authorization","Bearer " + accessToken);
                })
                .retrieve()
                .bodyToMono(GoogleProfileResponseDto.class)
                .block();

        if(profileResponse == null || profileResponse.getEmailAddresses() == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }

        String socialEmail = profileResponse.getEmailAddresses().get(0).getValue();

        // 현재 로그인 되어있는 SNS 계정이 아닌 다른 계정으로 탈퇴를 시도했다면 예외 발생
        if(!Objects.equals(tokenEmail, socialEmail)) {
            userRepository.findByEmail(socialEmail).ifPresentOrElse(
                    // 다른 계정이 브로콜리에 가입된 계정이라면
                    user -> {
                        // 탈퇴 시키지 않고 예외 처리
                        throw new GlobalException(ErrorCode.INVALID_SOCIAL_EMAIL, "현재 로그인한 SNS 계정과 다른 계정입니다.");
                    },
                    // 소셜 계정이 브로콜리에 없는 계정이라면
                    () -> {
                        // SNS와의 연동 끊기
                        loginWebClient
                                .post()
                                .uri(uriBuilder -> uriBuilder
                                        .path("/revoke")
                                        .queryParam("token", accessToken)
                                        .build())
                                .headers(headers -> headers.add("Content-type", "application/x-www-form-urlencoded"))
                                .exchangeToMono(response -> response.bodyToMono(Map.class).map(map -> {
                                    if(response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                                        throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                                    }

                                    return map;
                                }))
                                .block();

                        throw new GlobalException(ErrorCode.INVALID_SOCIAL_EMAIL, "현재 로그인한 SNS 계정과 다른 계정입니다.");
                    }
            );
        }

        // SNS와의 연동 끊기
        loginWebClient
                .post()
                .uri(uriBuilder -> uriBuilder
                        .path("/revoke")
                        .queryParam("token", accessToken)
                        .build())
                .headers(headers -> headers.add("Content-type", "application/x-www-form-urlencoded"))
                .exchangeToMono(response -> response.bodyToMono(Map.class).map(map -> {
                    if(response.statusCode().is4xxClientError() || response.statusCode().is5xxServerError()) {
                        throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
                    }

                    return map;
                }))
                .block();

        // 없는 회원이면 예외 발생
        User user = userRepository.findByEmail(socialEmail).orElseThrow(() ->
                new GlobalException(ErrorCode.EMAIL_NON_EXISTENT, "존재하지 않는 회원입니다.")
        );

        // 이미 탈퇴한 회원이라면 예외 발생
        if(user.getDeletedAt() != null) {
            throw new GlobalException(ErrorCode.WITHDREW_USER, "탈퇴한 회원입니다.");
        }

        // 정상적인 접근이면 탈퇴 처리
        user.setRefreshToken(null);
        user.setDeletedAt(LocalDateTime.now());

        userRepository.save(user);

        return SocialWithdrawResponseDto.from(user);
    }
}
