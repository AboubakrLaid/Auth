package com.geoalert.auth.Repository;

import com.geoalert.auth.Enum.VerificationType;
import com.geoalert.auth.entity.VerificationCode;
import com.geoalert.auth.entity.User;

import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationCodeRepository extends JpaRepository<VerificationCode, Long> {
    VerificationCode findByUserAndType(User user, VerificationType type);
    boolean existsByUserAndType(User user, VerificationType type);
}
