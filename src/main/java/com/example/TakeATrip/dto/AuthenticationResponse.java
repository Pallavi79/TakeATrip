package com.example.TakeATrip.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@ToString
public class AuthenticationResponse {
    private String jwtToken;
    private String username;
    private String userId;
}
