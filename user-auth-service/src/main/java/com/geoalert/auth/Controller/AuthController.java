package com.geoalert.auth.Controller;


import com.geoalert.auth.Enum.VerificationType;
import com.geoalert.auth.Repository.AuthRepository;
import com.geoalert.auth.Repository.VerificationCodeRepository;
import com.geoalert.auth.dto.*;
import com.geoalert.auth.entity.User;
import com.geoalert.auth.entity.VerificationCode;
import com.geoalert.auth.security.JWTUtil;
import com.geoalert.auth.service.AuthService;
import com.geoalert.auth.service.UserInfoConfigManager;
import com.geoalert.auth.service.VerifficationCodeService;
import com.geoalert.auth.utils.ResponseHandler;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    JWTUtil jwtUtil;

    @Autowired
    AuthService authService;

    @Autowired
    VerificationCodeRepository verificationCodeRepository;

    @Autowired
    VerifficationCodeService  verifficationCodeService;

    @Autowired
    AuthRepository authRepository;

    @Autowired
    AuthenticationManager authenticationManager;
    
    @Autowired
    private UserInfoConfigManager userInfoConfigManager;

    @PostMapping("/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterDTO registerDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }
        if (authService.emailExists(registerDTO.getEmail())) {
            return ResponseHandler.generateResponse("Email is already in use", HttpStatus.BAD_REQUEST, null);
        }

        RegisterResponse response = authService.register(registerDTO);

        return ResponseHandler.generateResponse("User registered successfully", HttpStatus.OK, response);
    }




    @PostMapping("/login")
    public ResponseEntity<Object> login(@Valid @RequestBody LoginDTO loginDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }
        try {
            Authentication authenticate = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginDTO.getEmail(), loginDTO.getPassword()));
            UserDetails userDetails = userInfoConfigManager.loadUserByUsername(loginDTO.getEmail());

            // check if email is verified
            User user = authRepository.findByEmail(loginDTO.getEmail());

            if (!verifficationCodeService.isEmailVerified(user)) {
                return ResponseHandler.generateErrorResponse("Please verify your email before logging in.", HttpStatus.FORBIDDEN);
            }

            String jwt = jwtUtil.generateToken(userDetails.getUsername());
            String refreshToken = jwtUtil.generateRefreshToken(userDetails.getUsername());
            LoginResponse loginResponse = LoginResponse
                    .builder()
                    .accessToken(jwt)
                    .refreshToken(refreshToken)
                    .build();
            return ResponseHandler.generateResponse("User logged in successfully", HttpStatus.OK, loginResponse);
        }
        catch (Exception e)
        {
            return ResponseHandler.generateErrorResponse("Incorrect email or password", HttpStatus.UNAUTHORIZED);
        }
    }




    @PostMapping("/verify-email")
    public ResponseEntity<Object> verifyEmail(@Valid @RequestBody VerifyEmailDTO verifyEmailDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }
        User user = authRepository.findByEmail(verifyEmailDTO.getEmail());
        if (user == null) {
            return ResponseHandler.generateErrorResponse("User not found", HttpStatus.NOT_FOUND);
        }
        VerificationCode verificationCode = verificationCodeRepository.findByUserAndType(user, VerificationType.EMAIL_VERIFICATION);

        if (verificationCode == null || !verificationCode.getCode().equals(verifyEmailDTO.getCode())) {
            return ResponseHandler.generateErrorResponse("Invalid verification code", HttpStatus.BAD_REQUEST);
        }

        if (verificationCode.getExpiryDate().isBefore(LocalDateTime.now())) {
            return ResponseHandler.generateErrorResponse("Verification code expired", HttpStatus.BAD_REQUEST);

        }

        verificationCodeRepository.delete(verificationCode);

        return ResponseHandler.generateResponse("Email verified successfully", HttpStatus.OK, null);
    }




    @PostMapping("/resend-code")
    public ResponseEntity<Object> resendCode(@Valid @RequestBody ResendEmailVerificationCodeDTO request, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }
        User user = authRepository.findByEmail(request.getEmail());
        if (user == null) {
            return ResponseHandler.generateErrorResponse("User not found", HttpStatus.NOT_FOUND);
        }
        VerificationCode verificationCode =  verificationCodeRepository.findByUserAndType(user, VerificationType.EMAIL_VERIFICATION);
        if (verificationCode == null) {
            return ResponseHandler.generateResponse("Email already verified", HttpStatus.OK, null);
        }
        verifficationCodeService.sendEmailVerificationCode(user);

        return ResponseHandler.generateResponse("New verification code sent", HttpStatus.OK, null);


    }






    @PostMapping("/refresh-token")
    public ResponseEntity<Object> refreshAccessToken(@Valid @RequestBody RefreshTokenDTO refreshTokenDTO, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return ResponseHandler.generateValidationErrorResponse(bindingResult, HttpStatus.BAD_REQUEST);
        }

        String refreshToken = refreshTokenDTO.getRefreshToken();

        if (refreshToken == null || !jwtUtil.validateRefreshToken(refreshToken)) {
            return ResponseHandler.generateErrorResponse("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }

        String email = jwtUtil.extractEmail(refreshToken, true);
        RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse(jwtUtil.generateToken(email));

        return ResponseHandler.generateResponse("Token refreshed successfully", HttpStatus.OK, refreshTokenResponse);
    }


    @GetMapping("/protected")
    public ResponseEntity<Object> getProtectedData() {
        return ResponseHandler.generateResponse("Access granted to protected resource", HttpStatus.OK,
                Map.of("data", "This is a protected endpoint"));
    }
}
