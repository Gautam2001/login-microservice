package com.Login.Entity;

import java.time.Instant;

import com.Login.Entity.UserAuthEntity.Role;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Entity
@Table(name = "signup_staging")
public class SignupStagingEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, nullable = false)
	private String username; // email

	@Column(nullable = false)
	private String name;

	@Column(nullable = false)
	private String passwordHash;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private Role role;

	@Column(nullable = false)
	private String otp;

	@Column(nullable = false)
	private Instant expiry;

	@Column(nullable = false)
	private int otpResendCount = 0;

	public SignupStagingEntity(String username, String name, String passwordHash, Role role, String otp,
			Instant expiry) {
		super();
		this.username = username;
		this.name = name;
		this.passwordHash = passwordHash;
		this.role = role;
		this.otp = otp;
		this.expiry = expiry;
		otpResendCount = 0;
	}

}
