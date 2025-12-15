CREATE TABLE users (
    id                              INTEGER     PRIMARY KEY AUTOINCREMENT,
    username                        CHAR(50)    UNIQUE NOT NULL,
    password_hash                   CHAR(255)   NOT NULL,
    email                           CHAR(100)   UNIQUE NOT NULL,
    display_name                    CHAR(100),
    lockout_until                   TIMESTAMP,
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    profile_color                   CHAR(7)     DEFAULT '#2b6cb0',
    login_attempts_since_successful INTEGER     DEFAULT 0
);

CREATE TABLE comments (
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    content                         TEXT        NOT NULL,
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (username, created_at)
);

CREATE TABLE login_attempts (
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    attempt_time                    TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
    success                         BOOLEAN     NOT NULL,
    ip_address                      CHAR(45),
    PRIMARY KEY (username, attempt_time, ip_address)
);

CREATE TABLE sessions (
    session_id                      CHAR(100)   PRIMARY KEY,
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    created_at                      TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE password_resets (
    username                        CHAR(50)    REFERENCES users(username) ON DELETE CASCADE,
    reset_token                     CHAR(100)   UNIQUE NOT NULL,
    expires_at                      TIMESTAMP   NOT NULL,
    PRIMARY KEY (username, reset_token)
);
