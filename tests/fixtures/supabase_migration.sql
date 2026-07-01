CREATE TABLE users (id UUID PRIMARY KEY, email TEXT, password_hash TEXT);
CREATE TABLE payments (id UUID PRIMARY KEY, user_id UUID, amount NUMERIC);
-- RLS never enabled
