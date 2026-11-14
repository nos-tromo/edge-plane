-- The schema a fresh database of the pinned Authelia image (4.39.20) holds after
-- `authelia storage migrate up` (schema version 24): sqlite_master's statements,
-- verbatim and in creation order. Used by audit/tests/authelia_fixture.py; refresh
-- it with the same command when the image is bumped (docs/images.md).
CREATE TABLE identity_verification (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    jti VARCHAR(36),
    iat DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    issued_ip VARCHAR(39) NOT NULL,
    exp DATETIME NOT NULL,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    consumed DATETIME NULL DEFAULT NULL,
    consumed_ip VARCHAR(39) NULL DEFAULT NULL
, revoked DATETIME NULL DEFAULT NULL, revoked_ip VARCHAR(39) NULL DEFAULT NULL);
CREATE UNIQUE INDEX identity_verification_jti_key ON identity_verification (jti);
CREATE TABLE totp_configurations (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL DEFAULT NULL,
    username VARCHAR(100) NOT NULL,
    issuer VARCHAR(100),
    algorithm VARCHAR(6) NOT NULL DEFAULT 'SHA1',
    digits INTEGER NOT NULL DEFAULT 6,
    period INTEGER NOT NULL DEFAULT 30,
    secret BLOB NOT NULL
);
CREATE UNIQUE INDEX totp_configurations_username_key ON totp_configurations (username);
CREATE TABLE duo_devices (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) NOT NULL,
    device VARCHAR(32) NOT NULL,
    method VARCHAR(16) NOT NULL
);
CREATE UNIQUE INDEX duo_devices_username_key ON duo_devices (username);
CREATE TABLE user_preferences (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(100) NOT NULL,
    second_factor_method VARCHAR(11) NOT NULL
);
CREATE UNIQUE INDEX user_preferences_username_key ON user_preferences (username);
CREATE TABLE encryption (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100),
    value BLOB NOT NULL
);
CREATE UNIQUE INDEX encryption_name_key ON encryption (name);
CREATE TABLE user_opaque_identifier (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    service VARCHAR(20) NOT NULL,
    sector_id VARCHAR(255) NOT NULL,
    username VARCHAR(100) NOT NULL,
    identifier CHAR(36) NOT NULL
);
CREATE UNIQUE INDEX user_opaque_identifier_lookup_key ON user_opaque_identifier (service, sector_id, username);
CREATE UNIQUE INDEX user_opaque_identifier_identifier_key ON user_opaque_identifier (identifier);
CREATE TABLE authentication_logs (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    successful BOOLEAN NOT NULL,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    username VARCHAR(100) NOT NULL,
    auth_type VARCHAR(8) NOT NULL DEFAULT '1FA',
    remote_ip VARCHAR(39) NULL DEFAULT NULL,
    request_uri TEXT,
    request_method VARCHAR(8) NOT NULL DEFAULT ''
);
CREATE INDEX authentication_logs_username_idx ON authentication_logs (time, username, auth_type);
CREATE INDEX authentication_logs_remote_ip_idx ON authentication_logs (time, remote_ip, auth_type);
CREATE TABLE migrations (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    applied DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version_before INTEGER NULL DEFAULT NULL,
    version_after INTEGER NOT NULL,
    application_version VARCHAR(128) NOT NULL
);
CREATE TABLE oauth2_blacklisted_jti (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    signature VARCHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX oauth2_blacklisted_jti_signature_key ON oauth2_blacklisted_jti (signature);
CREATE TABLE oauth2_consent_preconfiguration (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    client_id VARCHAR(255) NOT NULL,
    subject CHAR(36) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL DEFAULT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    scopes TEXT NOT NULL,
    audience TEXT NULL, requested_claims TEXT NULL, signature_claims CHAR(64) NULL, granted_claims TEXT DEFAULT '',
    CONSTRAINT oauth2_consent_preconfiguration_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE TABLE oauth2_par_context (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    signature VARCHAR(255) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scopes TEXT NOT NULL,
    audience TEXT NOT NULL,
    handled_response_types TEXT NOT NULL,
    response_mode TEXT NOT NULL,
    response_mode_default TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL
);
CREATE UNIQUE INDEX oauth2_par_context_signature_key ON oauth2_par_context (signature);
CREATE TABLE webauthn_credentials (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME NULL DEFAULT NULL,
    rpid VARCHAR(512) NOT NULL,
    username VARCHAR(100) NOT NULL,
    description VARCHAR(64) NOT NULL,
    kid VARCHAR(512) NOT NULL,
    aaguid CHAR(36) NULL,
    attestation_format VARCHAR(32),
    attachment VARCHAR(64),
    transport VARCHAR(64) DEFAULT '',
    sign_count INTEGER DEFAULT 0,
    clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
    legacy BOOLEAN NOT NULL DEFAULT FALSE,
    discoverable BOOLEAN NOT NULL,
    present BOOLEAN NOT NULL DEFAULT FALSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    public_key BLOB NOT NULL
, attestation BLOB NULL DEFAULT NULL, attestation_type VARCHAR(32) NOT NULL DEFAULT '');
CREATE UNIQUE INDEX webauthn_credentials_kid_key ON webauthn_credentials (kid);
CREATE UNIQUE INDEX webauthn_credentials_lookup_key ON webauthn_credentials (rpid, username, description);
CREATE TABLE webauthn_users (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    rpid VARCHAR(512) NOT NULL,
    username VARCHAR(100) NOT NULL,
    userid CHAR(64) NOT NULL
);
CREATE UNIQUE INDEX webauthn_users_lookup_key ON webauthn_users (rpid, username);
CREATE TABLE one_time_code (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    public_id CHAR(36) NOT NULL,
    signature VARCHAR(128) NOT NULL,
    issued DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    issued_ip VARCHAR(39) NOT NULL,
    expires DATETIME NOT NULL,
    username VARCHAR(100) NOT NULL,
    intent VARCHAR(100) NOT NULL,
    consumed DATETIME NULL DEFAULT NULL,
    consumed_ip VARCHAR(39) NULL DEFAULT NULL,
    revoked DATETIME NULL DEFAULT NULL,
    revoked_ip VARCHAR(39) NULL DEFAULT NULL,
    code BLOB NOT NULL
);
CREATE UNIQUE INDEX one_time_code_lookup_key ON one_time_code (signature, username);
CREATE TABLE totp_history (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(100) NOT NULL,
    step CHAR(64) NOT NULL
);
CREATE UNIQUE INDEX totp_history_lookup_key ON totp_history (username, step);
CREATE TABLE oauth2_consent_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    subject CHAR(36) NULL DEFAULT NULL,
    authorized BOOLEAN NOT NULL DEFAULT FALSE,
    granted BOOLEAN NOT NULL DEFAULT FALSE,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME NULL DEFAULT NULL,
    form_data TEXT NOT NULL,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    preconfiguration INTEGER NULL DEFAULT NULL, granted_claims TEXT NULL, expires_at TIMESTAMP NOT NULL DEFAULT '2000-01-01 00:00:00.000000000+00:00',
    CONSTRAINT oauth2_consent_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT oauth2_consent_session_preconfiguration_fkey
        FOREIGN KEY (preconfiguration)
            REFERENCES oauth2_consent_preconfiguration (id) ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE UNIQUE INDEX oauth2_consent_session_challenge_id_key ON oauth2_consent_session (challenge_id);
CREATE TABLE oauth2_authorization_code_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    signature VARCHAR(255) NOT NULL,
    subject CHAR(36) NOT NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL,
    CONSTRAINT oauth2_authorization_code_session_challenge_id_fkey
        FOREIGN KEY (challenge_id)
            REFERENCES oauth2_consent_session (challenge_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT oauth2_authorization_code_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX oauth2_authorization_code_session_request_id_idx ON oauth2_authorization_code_session (request_id);
CREATE INDEX oauth2_authorization_code_session_client_id_idx ON oauth2_authorization_code_session (client_id);
CREATE INDEX oauth2_authorization_code_session_client_id_subject_idx ON oauth2_authorization_code_session (client_id, subject);
CREATE TABLE oauth2_access_token_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NULL DEFAULT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    signature VARCHAR(768) NOT NULL,
    subject CHAR(36) NULL DEFAULT NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL,
    CONSTRAINT oauth2_access_token_session_challenge_id_fkey
        FOREIGN KEY (challenge_id)
            REFERENCES oauth2_consent_session (challenge_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT oauth2_access_token_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX oauth2_access_token_session_request_id_idx ON oauth2_access_token_session (request_id);
CREATE INDEX oauth2_access_token_session_client_id_idx ON oauth2_access_token_session (client_id);
CREATE INDEX oauth2_access_token_session_client_id_subject_idx ON oauth2_access_token_session (client_id, subject);
CREATE TABLE oauth2_refresh_token_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    signature VARCHAR(255) NOT NULL,
    subject CHAR(36) NOT NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL,
    CONSTRAINT oauth2_refresh_token_session_challenge_id_fkey
        FOREIGN KEY (challenge_id)
            REFERENCES oauth2_consent_session (challenge_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT oauth2_refresh_token_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX oauth2_refresh_token_session_request_id_idx ON oauth2_refresh_token_session (request_id);
CREATE INDEX oauth2_refresh_token_session_client_id_idx ON oauth2_refresh_token_session (client_id);
CREATE INDEX oauth2_refresh_token_session_client_id_subject_idx ON oauth2_refresh_token_session (client_id, subject);
CREATE TABLE oauth2_pkce_request_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    signature VARCHAR(255) NOT NULL,
    subject CHAR(36) NOT NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL,
    CONSTRAINT oauth2_pkce_request_session_challenge_id_fkey
        FOREIGN KEY (challenge_id)
            REFERENCES oauth2_consent_session (challenge_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT oauth2_pkce_request_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX oauth2_pkce_request_session_request_id_idx ON oauth2_pkce_request_session (request_id);
CREATE INDEX oauth2_pkce_request_session_client_id_idx ON oauth2_pkce_request_session (client_id);
CREATE INDEX oauth2_pkce_request_session_client_id_subject_idx ON oauth2_pkce_request_session (client_id, subject);
CREATE TABLE oauth2_openid_connect_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NOT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    signature VARCHAR(255) NOT NULL,
    subject CHAR(36) NOT NULL,
    requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL,
    CONSTRAINT oauth2_openid_connect_session_challenge_id_fkey
        FOREIGN KEY (challenge_id)
            REFERENCES oauth2_consent_session (challenge_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT oauth2_openid_connect_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX oauth2_openid_connect_session_request_id_idx ON oauth2_openid_connect_session (request_id);
CREATE INDEX oauth2_openid_connect_session_client_id_idx ON oauth2_openid_connect_session (client_id);
CREATE INDEX oauth2_openid_connect_session_client_id_subject_idx ON oauth2_openid_connect_session (client_id, subject);
CREATE TABLE oauth2_device_code_session (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    challenge_id CHAR(36) NULL DEFAULT NULL,
    request_id VARCHAR(40) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    signature VARCHAR(255) NOT NULL,
    user_code_signature VARCHAR(255) NOT NULL,
    status INTEGER NOT NULL,
    subject CHAR(36) NULL DEFAULT NULL,
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    checked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    requested_scopes TEXT NOT NULL,
    granted_scopes TEXT NOT NULL,
    requested_audience TEXT NULL DEFAULT '',
    granted_audience TEXT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT FALSE,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    form_data TEXT NOT NULL,
    session_data BLOB NOT NULL,
    CONSTRAINT oauth2_device_code_session_challenge_id_fkey
        FOREIGN KEY (challenge_id)
            REFERENCES oauth2_consent_session (challenge_id) ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT oauth2_device_code_session_subject_fkey
        FOREIGN KEY (subject)
            REFERENCES user_opaque_identifier (identifier) ON UPDATE CASCADE ON DELETE RESTRICT
);
CREATE INDEX oauth2_device_code_session_request_id_idx ON oauth2_device_code_session (request_id);
CREATE INDEX oauth2_device_code_session_client_id_idx ON oauth2_device_code_session (client_id);
CREATE INDEX oauth2_device_code_session_client_id_subject_idx ON oauth2_device_code_session (client_id, subject);
CREATE TABLE cached_data (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL,
    name VARCHAR(20) NOT NULL,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    value BLOB NOT NULL
);
CREATE UNIQUE INDEX cached_data_name_key ON cached_data (name);
CREATE TABLE banned_user (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires TIMESTAMP NULL DEFAULT NULL,
    expired TIMESTAMP NULL DEFAULT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    username VARCHAR(100) NOT NULL,
    source VARCHAR(10) NOT NULL,
    reason VARCHAR(100) NULL DEFAULT NULL
);
CREATE INDEX banned_user_username_idx ON banned_user (username);
CREATE INDEX banned_user_lookup_idx ON banned_user (username, revoked, expires, expired);
CREATE INDEX banned_user_list_idx ON banned_user (revoked, expires, expired);
CREATE TABLE banned_ip (
    id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires TIMESTAMP NULL DEFAULT NULL,
    expired TIMESTAMP NULL DEFAULT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    ip VARCHAR(39) NOT NULL,
    source VARCHAR(10) NOT NULL,
    reason VARCHAR(100) NULL DEFAULT NULL
);
CREATE INDEX banned_ip_ip_idx ON banned_ip (ip);
CREATE INDEX banned_ip_lookup_idx ON banned_ip (ip, revoked, expires, expired);
CREATE INDEX banned_ip_list_idx ON banned_ip (revoked, expires, expired);
