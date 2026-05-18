CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  password TEXT,
  role VARCHAR(50)
);

CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  user_email VARCHAR(100),
  action TEXT,
  ip VARCHAR(100),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Senha para ambos é '123456' (hash gerado pelo bcrypt)
INSERT INTO users (name, email, password, role) VALUES 
('Administrador', 'admin@fintech.com', '$2b$10$X7.m5C5Z.uL9zZ7qK.Z.ue0.uL9zZ7qK.Z.ue0X7.m5C5Z.uL9zZ7', 'admin'),
('Usuario Comum', 'user@fintech.com', '$2b$10$X7.m5C5Z.uL9zZ7qK.Z.ue0.uL9zZ7qK.Z.ue0X7.m5C5Z.uL9zZ7', 'user');