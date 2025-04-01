package com.geoalert.auth.service;

import com.geoalert.auth.Repository.AuthRepository;
import com.geoalert.auth.dto.RegisterDTO;
import com.geoalert.auth.dto.RegisterResponse;
import com.geoalert.auth.entity.User;
import com.geoalert.auth.Enum.Role;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;


@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
    private AuthRepository authRepository;

    @Autowired
    private VerifficationCodeService  verifficationCodeService;

    @Autowired
    private ModelMapper modelMapper;

    private static final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public AuthServiceImpl(AuthRepository authRepository, ModelMapper modelMapper) {
        this.authRepository = authRepository;
        this.modelMapper = modelMapper;
        this.verifficationCodeService = verifficationCodeService;
    }

    @Override
    public RegisterResponse register(RegisterDTO registerDTO) {

        // Map DTO to User entity
        User user = modelMapper.map(registerDTO, User.class);
        user.setPassword(passwordEncoder.encode(registerDTO.getPassword()));
        user.setCreatedAt(LocalDateTime.now());
        user.setRole(Role.USER);

        try {
            User savedUser = authRepository.save(user);

            verifficationCodeService.sendEmailVerificationCode(user);

            return modelMapper.map(savedUser, RegisterResponse.class);
        } catch (DataIntegrityViolationException e) {
            throw new RuntimeException("An error occurred while saving user. Possible duplicate email.");
        }
    }

    @Override
    public boolean emailExists(String email) {
        System.out.println(authRepository.findByEmail(email) != null);
        return authRepository.findByEmail(email) != null;
    }

}
