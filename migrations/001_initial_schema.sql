CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    roles TEXT NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_token ON user_tokens(token);
CREATE INDEX idx_user_tokens_expires_at ON user_tokens(expires_at);

-- API Logs Tabelle
CREATE TABLE api_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    route_id INTEGER REFERENCES routes(id),
    request_method TEXT NOT NULL,
    request_body JSONB,
    response_status INTEGER NOT NULL,
    response_body JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- API Schlüssel Tabelle
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key TEXT NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Index für API-Schlüssel-Suche
CREATE INDEX idx_api_keys_key ON api_keys(key); 