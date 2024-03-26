package com.hjson.websocket_rest_test.data.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class KakaoProfileResponseDtoElement {
    private Boolean has_email;
    private Boolean email_needs_agreement;
    private Boolean is_email_valid;
    private Boolean is_email_verified;
    private String email;
    private Boolean has_birthyear;
    private Boolean birthyear_needs_agreement;
    private Short birthyear;
    private Boolean has_gender;
    private Boolean gender_needs_agreement;
    private String gender;
}
