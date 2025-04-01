package com.geoalert.auth.service;

import com.geoalert.auth.entity.User;
import com.geoalert.auth.entity.VerificationCode;

public interface VerifficationCodeService {
    void sendEmailVerificationCode(User user);
    boolean isEmailVerified(User user);
}
