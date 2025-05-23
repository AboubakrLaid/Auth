package com.geoalert.auth.dto;


import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class ResendEmailVerificationCodeDTO {
    @NotBlank(message = "Email is required")
    private String email;
}
