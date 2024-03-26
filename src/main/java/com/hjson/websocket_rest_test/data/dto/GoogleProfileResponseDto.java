package com.hjson.websocket_rest_test.data.dto;

import com.hjson.websocket_rest_test.data.entity.User;
import com.hjson.websocket_rest_test.exception.GlobalException;
import com.hjson.websocket_rest_test.exception.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class GoogleProfileResponseDto {
    private String resourceName;
    private String etag;
    private List<Genders> genders;
    private List<Birthdays> birthdays;
    private List<EmailAddresses> emailAddresses;

    public User toUserEntity() {
        String email;
        if (emailAddresses == null) {
            throw new GlobalException(ErrorCode.UNEXPECTED_SOCIAL_ERROR, "SNS와의 연결 중 예상하지 못한 오류가 발생하였습니다.");
        }
        email = emailAddresses.get(0).getValue();

        return new User(
                email,
                null,
                null,
                User.Provider.google,
                LocalDateTime.now(),
                LocalDateTime.now(),
                null
        );
    }

    @Getter
    private static class Genders {
        private Map metadata;
        private String value;
        private String formattedValue;
    }

    @Getter
    public static class Birthdays {
        private Map metadata;
        private BirthdaysDate date;
    }

    @Getter
    public static class BirthdaysDate {
        private Short year;
        private Short month;
        private Short day;
    }

    @Getter
    public static class EmailAddresses {
        private Map metadata;
        private String value;
    }
}
