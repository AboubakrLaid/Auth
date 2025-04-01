package com.geoalert.auth.entity;

import com.geoalert.auth.Enum.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder
@Table(uniqueConstraints = { @UniqueConstraint(columnNames = "email")})
@Entity(name = "Users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    private String firstName;
    private String lastName;
    private String password;

    @Column(nullable = false, unique = true)
    private String email;
    private String phoneNumber;

    @Enumerated(EnumType.STRING)
    private Role role;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public String getUsername(){
        return firstName + " " + lastName;
    }
}
