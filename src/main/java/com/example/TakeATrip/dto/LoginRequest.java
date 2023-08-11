package com.example.TakeATrip.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class LoginRequest {
    private String email;
    private String password;
}
