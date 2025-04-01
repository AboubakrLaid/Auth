package com.geoalert.auth.utils;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;

import java.util.HashMap;
import java.util.Map;

public class ResponseHandler {
    public static ResponseEntity<Object> generateResponse(String message, HttpStatus status, Object responseObj) {
        Map<String, Object> map = new HashMap<String, Object>();
        map.put("message", message);
        map.put("status", status.value());
        map.put("data", responseObj);
        return new ResponseEntity<Object>(map, status);
    }


    public static ResponseEntity<Object> generateValidationErrorResponse(BindingResult bindingResult, HttpStatus status) {
        Map<String, Object> errors = new HashMap<>();
        errors.put("message", "Validation failed");
        errors.put("status", status.value());

        Map<String, String> fieldErrors = new HashMap<>();
        bindingResult.getFieldErrors().forEach(error -> fieldErrors.put(error.getField(), error.getDefaultMessage()));

        errors.put("errors", fieldErrors);
        return new ResponseEntity<>(errors, status);
    }

    public static ResponseEntity<Object> generateErrorResponse(String message, HttpStatus status) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("message", message);
        errorResponse.put("status", status.value());
        return new ResponseEntity<>(errorResponse, status);
    }
}
