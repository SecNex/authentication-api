ALTER TABLE user_tokens ADD COLUMN token_type VARCHAR(20) NOT NULL DEFAULT 'access';
ALTER TABLE user_tokens ADD COLUMN refresh_token_id UUID REFERENCES user_tokens(id); 