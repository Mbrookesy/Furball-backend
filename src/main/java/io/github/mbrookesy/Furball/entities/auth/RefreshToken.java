package io.github.mbrookesy.Furball.entities.auth;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    private UserEntity user;

    @Column(nullable = false)
    private Instant expiryDate;

    public void setToken(String token) {
        this.token = token;
    }

    public void setUser(UserEntity user) {
        this.user = user;
    }

    public void setExpiryDate(Instant expiryDate) {
        this.expiryDate = expiryDate;
    }

    public Instant getExpiryDate() {
        return expiryDate;
    }

    public UserEntity getUser() {
        return user;
    }

    public String getToken() {
        return token;
    }
}


