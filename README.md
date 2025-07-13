# 🔐 Login Microservice

A secure, reusable login microservice built with **Spring Boot**, featuring:

- ✅ JWT-based authentication (Access + Refresh tokens with RSA)
- ✉️ OTP-based user signup and password reset
- 🔁 Token refresh and logout flows
- 🛡️ Admin protection and role-based restrictions

This microservice is designed to serve multiple client applications like **Wrap and Wow**, **Messenger**, and more.

---

## 🧰 Tech Stack

- Java 17+
- Spring Boot
- Spring Security
- Spring Data JPA
- PostgreSQL
- JWT (RSA)
- JavaMail (SMTP)
- Maven

---

## ⚙️ Architecture Overview

### 🔒 Security

- `SecurityConfig`: Configures CORS, disables CSRF, registers filters
- `JwtAuthenticationFilter`: Intercepts and validates access tokens
- `JwtUtil`: Handles access and refresh token generation/validation using **RSA**
- `CustomUserDetailsService` + `CustomUserDetails`: Load user information from DB
- `.pem` keys are read from `resources/keys` via `RsaKeyUtil`

### 🌍 Global Error Handling

- `GlobalExceptionHandler`: Catches and formats all application exceptions
- `CommonUtils`: Reusable helpers for logging, response formatting, and error generation

---

## 🧾 API Endpoints

### ✅ Health

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ping` | `GET` | Health check |

### 👤 Signup Flow

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/request-signup` | `POST` | Takes user info, generates OTP, emails it, stores in `signup_staging` |
| `/auth/signup` | `POST` | Validates OTP and saves user to `user_auth` |

### 🔐 Login / Token Flow

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/login` | `POST` | Verifies credentials, returns access + refresh tokens |
| `/auth/logout` | `POST` | Invalidates refresh token via cookie clearing |
| `/auth/refresh` | `POST` | Generates new access token from refresh token |

### 🔑 Forgot Password Flow

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/request-forgot-password` | `POST` | Sends OTP to email after validation |
| `/auth/validate-otp` | `POST` | Validates OTP, returns short-lived reset-token |
| `/auth/forgot-password` | `POST` | Sets new password using reset-token |
| `/auth/request-reset-password` | `POST` | Validates old password, sends OTP |
| `/auth/reset-password` | `POST` | Validates OTP and updates password |

### 🔁 OTP Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/resend-otp` | `POST` | Regenerates and resends OTP for signup or password reset |

---

## 🧩 Database Tables

### `user_auth`

| Field | Type | Description |
|-------|------|-------------|
| `user_id` | UUID | Primary key |
| `username` | String | Email (unique) |
| `name` | String | Full name |
| `password_hash` | String | Hashed password |
| `role` | Enum | `USER`, `ADMIN` |
| `account_status` | Enum | `ACTIVE`, `INACTIVE` |
| `created_at`, `updated_at` | Timestamp | Auto-managed |

### `signup_staging`

| Field | Description |
|-------|-------------|
| `username`, `name`, `password_hash`, `role`, `otp`, `expiry` |

### `password_staging`

| Field | Description |
|-------|-------------|
| `username`, `otp`, `expiry` |

---

## 🛡️ Security Notes

- Uses **RSA asymmetric keys** (`private_key.pem`, `public_key.pem`) for JWT
- OTP is valid for **10 minutes**
- `.pem` files and secrets should **never be committed to Git**
- Limit OTP resend attempts for abuse protection

---

## 📦 Local Setup

### 📋 Prerequisites

- Java 17+
- PostgreSQL
- Maven

### 🛠️ Setup Steps

1. Clone the repo:
   ```bash
   git clone https://github.com/your-username/login-microservice.git
   cd login-microservice

    Create and configure your PostgreSQL database:

CREATE DATABASE login_db;
CREATE USER login_user WITH ENCRYPTED PASSWORD 'loginpass';
GRANT ALL PRIVILEGES ON DATABASE login_db TO login_user;

Create a .env file (or edit application.properties) with:

spring.datasource.url=jdbc:postgresql://localhost:5432/login_db
spring.datasource.username=login_user
spring.datasource.password=loginpass

spring.mail.username=your-email@gmail.com
spring.mail.password=your-app-password

Place your RSA keys in src/main/resources/keys/

    private_key.pem

    public_key.pem

Run the application:

    mvn spring-boot:run

📂 Recommended .gitignore

# Java
*.class
*.log

# Maven
target/
.mvn/

# Keys & Secrets
src/main/resources/keys/
.env
*.pem

# IDE
.idea/
*.iml
*.ipr
*.iws
.vscode/

# OS
.DS_Store
Thumbs.db

🔗 Related Projects

    Wrap and Wow

    Messenger (Upcoming)

👨‍💻 Author

Gautam Singhal
