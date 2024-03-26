package com.hjson.websocket_rest_test.util;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Component;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Component
public class EmailAuthUtil {
    private final JavaMailSender javaMailSender;
    private final SpringTemplateEngine templateEngine;
    private final RedisTemplate<String, String> redisTemplate;

    public EmailAuthUtil(JavaMailSender javaMailSender, SpringTemplateEngine templateEngine, RedisTemplate<String, String> redisTemplate) {
        this.javaMailSender = javaMailSender;
        this.templateEngine = templateEngine;
        this.redisTemplate = redisTemplate;
    }

    private String createCode() {
        int leftLimit = 48; // 0
        int rightLimit = 122; // z
        int length = 6;

        SecureRandom random = new SecureRandom();

        return random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(length)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
    }

    private MimeMessage createEmail(String email, String code, Type type) throws MessagingException {
        String title = "[WebSocket Test] " + type.getText() + " 인증코드 안내";

        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        HashMap<String, String> emailValues = new HashMap<>();
        emailValues.put("type", type.getText());
        emailValues.put("code", code);

        Context context = new Context();
        emailValues.forEach(context::setVariable);

        String html = templateEngine.process("mail.html", context);

        helper.setTo(email);
        helper.setFrom("WebSocket Test <bplabcode@gmail.com>");
        helper.setSubject(title);
        helper.setText(html, true);

        return message;
    }

    public void sendEmail(String email, Type type) throws NoSuchAlgorithmException, MessagingException {
        String code = createCode();
        MimeMessage message = createEmail(email, code, type);

        HashOperations<String, String, String> hop = redisTemplate.opsForHash();
        Map<String, String> map = new HashMap<>();
        map.put("code", code);
        map.put("type", String.valueOf(type));
        hop.putAll(email, map);

        Duration expiredDuration = Duration.ofSeconds(600);
        redisTemplate.expire(email, expiredDuration);

        javaMailSender.send(message);
    }

    public boolean verifyCode(String email, String code, Type type) {
        HashOperations<String, String, String> hop = redisTemplate.opsForHash();

        if(!Objects.equals(hop.get(email, "type"), String.valueOf(type))) {
            return false;
        }

        return Objects.equals(hop.get(email, "code"), code);
    }

    public boolean deleteCode(String email) {
        return Boolean.TRUE.equals(redisTemplate.delete(email));
    }

    @AllArgsConstructor
    @Getter
    public enum Type {
        REGISTER("회원가입"),
        RESET("비밀번호 재설정");

        private final String text;
    }
}