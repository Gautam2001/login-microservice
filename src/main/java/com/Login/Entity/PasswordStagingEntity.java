package com.Login.Entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Entity
@Table(name = "password_staging")
public class PasswordStagingEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, nullable = false)
	private String username; // email

	@Column(nullable = false)
	private String otp;

	@Column(nullable = false)
	private Instant expiry;

	@Column(nullable = false)
	private int otpResendCount = 0;

	public PasswordStagingEntity(String username, String otp, Instant expiry) {
		super();
		this.username = username;
		this.otp = otp;
		this.expiry = expiry;
		otpResendCount = 0;
	}

}
