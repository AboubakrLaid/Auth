package com.geoalert.auth.Repository;

import com.geoalert.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthRepository extends JpaRepository<User, Long> {

//    User findByUsername(String username);
    User findByEmail(String email);
    boolean existsByEmail(String email);
}
