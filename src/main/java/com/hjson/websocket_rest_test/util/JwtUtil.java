package com.hjson.websocket_rest_test.util;

import com.hjson.websocket_rest_test.data.domain.Token;
import com.hjson.websocket_rest_test.data.entity.User.*;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Calendar;
import java.util.Date;

public class JwtUtil {
    public static Token createToken(String email, Provider provider, String accessSecretKey, String refreshSecretKey) {
        String accessToken = createAccessToken(email, provider, accessSecretKey);
        String refreshToken = createRefreshToken(email, refreshSecretKey);

        return new Token(accessToken, refreshToken);
    }

    public static Token deleteToken() {
        return new Token("", "");
    }

    public static boolean isExpired(String token, String secretKey) {
        Date expiredDate = getExpiredDate(token, secretKey);
        return expiredDate.before(new Date());
    }

    public static boolean canRefreshRefreshToken(String token, String secretKey) {
        Date expiredDate = getExpiredDate(token, secretKey);

        Calendar cal = Calendar.getInstance();
        cal.setTime(expiredDate);
        cal.add(Calendar.DATE, -30);
        Date canRefreshDate = cal.getTime();

        return canRefreshDate.before(new Date());
    }

    public static String getEmail(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("email", String.class);
    }

    public static String createAccessToken(String email, Provider provider, String secretKey) {
        Claims accessTokenClaims = Jwts.claims();
        accessTokenClaims.put("email", email);
        accessTokenClaims.put("provider", provider);

        long accessTokenExpiredMs = 1000 * 60 * 60 * 12L; // 12시간

        return Jwts.builder()
                .setClaims(accessTokenClaims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpiredMs))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public static String createRefreshToken(String email, String secretKey) {
        Claims refreshTokenClaims = Jwts.claims();
        refreshTokenClaims.put("email", email);

        long refreshTokenExpiredMs = 1000 * 60 * 60 * 24 * 60L; // 2달

        return Jwts.builder()
                .setClaims(refreshTokenClaims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpiredMs))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    private static Date getExpiredDate(String token, String secretKey) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getExpiration();
    }
}