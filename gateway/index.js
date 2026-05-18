const express = require("express");
const { createProxyMiddleware } = require("http-proxy-middleware");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");

const app = express();

app.use(helmet());
app.use(cors());

// Prevenção de Força Bruta no Gateway
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Muitas requisições deste IP, tente novamente mais tarde.",
});
app.use(limiter);

// Roteamento corrigido com pathRewrite
app.use(
  "/auth",
  createProxyMiddleware({
    target: "http://auth-service:3001",
    changeOrigin: true,
    pathRewrite: { "^/auth": "" }, // Corta o "/auth" antes de mandar pro serviço
  }),
);

app.use(
  "/users",
  createProxyMiddleware({
    target: "http://user-service:3002",
    changeOrigin: true,
    pathRewrite: { "^/users": "" }, // Corta o "/users" antes de mandar pro serviço
  }),
);

app.listen(3000, () => console.log("API Gateway rodando na porta 3000"));
