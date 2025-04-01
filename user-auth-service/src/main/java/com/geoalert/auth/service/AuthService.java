package com.geoalert.auth.service;

import com.geoalert.auth.dto.RegisterDTO;
import com.geoalert.auth.dto.RegisterResponse;

public interface AuthService {
    RegisterResponse register(RegisterDTO registerDTO);
    boolean emailExists(String email);
}
