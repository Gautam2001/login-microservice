package com.Login.Entity;

import java.time.LocalDateTime;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@Entity
@Table(name = "user_auth")
public class UserAuthEntity {

	@Id
	@GeneratedValue
	private UUID userId;

	@Column(unique = true, nullable = false)
	private String username; // email

	@Column(nullable = false)
	private String name;

	@Column(nullable = false)
	private String passwordHash;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private Role role;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false)
	private AccountStatus accountStatus;

	@Column(nullable = false, updatable = false)
	private LocalDateTime createdAt;

	@Column(nullable = false)
	private LocalDateTime updatedAt;

	public enum Role {
		USER, ADMIN, SUPERADMIN
	}

	public enum AccountStatus {
		ACTIVE, INACTIVE
	}

	@PrePersist
	protected void onCreate() {
		this.createdAt = LocalDateTime.now();
		this.updatedAt = LocalDateTime.now();
		this.accountStatus = AccountStatus.ACTIVE;
	}

	@PreUpdate
	protected void onUpdate() {
		this.updatedAt = LocalDateTime.now();
	}

	public UserAuthEntity(String username, String name, String passwordHash, Role role) {
		super();
		this.username = username;
		this.name = name;
		this.passwordHash = passwordHash;
		this.role = role;
	}

}
