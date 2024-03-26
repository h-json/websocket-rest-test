package com.hjson.websocket_rest_test.data.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class NaverProfileResponseDtoElement {
    private String id;
    private String gender;
    private String email;
    private Short birthyear;
}
