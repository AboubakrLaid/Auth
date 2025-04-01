package com.geoalert.auth.dto;


import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class RefreshTokenDTO {
    @NotEmpty(message = "Refresh token is required")
    private String refreshToken;
}
