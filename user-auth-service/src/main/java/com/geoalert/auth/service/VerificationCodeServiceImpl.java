package com.geoalert.auth.service;


import com.geoalert.auth.Enum.VerificationType;
import com.geoalert.auth.Repository.VerificationCodeRepository;
import com.geoalert.auth.entity.User;
import com.geoalert.auth.entity.VerificationCode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Random;

@Service
public class VerificationCodeServiceImpl implements VerifficationCodeService {

    @Autowired
    private VerificationCodeRepository verificationCodeRepository;

    @Autowired
    private EmailService emailService;


    @Override
    public void sendEmailVerificationCode(User user) {

        String code = String.format("%06d", new Random().nextInt(1000000));
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(1);

        VerificationCode verificationCode = verificationCodeRepository.findByUserAndType(user, VerificationType.EMAIL_VERIFICATION);

        if (verificationCode == null) {
            verificationCode = VerificationCode.builder()
                    .user(user)
                    .code(code)
                    .type(VerificationType.EMAIL_VERIFICATION)
                    .expiryDate(expiry)
                    .build();
        } else {
            verificationCode.setExpiryDate(expiry);
            verificationCode.setCode(code);
        }
        verificationCodeRepository.save(verificationCode);

        String subject = "Verify Your Email";
        String message = "Use this code to verify your email: " + code;
        emailService.sendEmail(user.getEmail(), subject, message);

    }

    @Override
    public boolean isEmailVerified(User user) {
        return !(verificationCodeRepository.existsByUserAndType(user, VerificationType.EMAIL_VERIFICATION));
    }
}
