/**
 * Configurações de Segurança Enterprise - Turbo.IA
 * Sistema robusto de segurança para ambiente corporativo
 * Proteção completa para 60+ padrões de uso empresarial
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

class SecurityConfig {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || this.generateSecureSecret();
    this.bcryptRounds = 12; // Custo computacional alto para segurança
    this.tokenExpiry = process.env.TOKEN_EXPIRY || '24h';
    this.refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '7d';
  }

  /**
   * Gerar secret seguro se não estiver definido
   */
  generateSecureSecret() {
    return crypto.randomBytes(64).toString('hex');
  }

  /**
   * Configurações do Helmet para segurança HTTP
   */
  getHelmetConfig() {
    return {
      // Content Security Policy
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "https://api.openai.com"],
          frameSrc: ["'none'"],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          manifestSrc: ["'self'"],
        },
      },

      // HSTS - HTTP Strict Transport Security
      hsts: {
        maxAge: 31536000, // 1 ano
        includeSubDomains: true,
        preload: true
      },

      // Proteção contra clickjacking
      frameguard: { action: 'deny' },

      // Proteção MIME type sniffing
      noSniff: true,

      // Proteção XSS
      xssFilter: true,

      // Referrer Policy
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },

      // Disable X-Powered-By header
      hidePoweredBy: true,

      // Proteção contra DNS Prefetch
      dnsPrefetchControl: { allow: false },

      // Proteção contra download de arquivos maliciosos
      ieNoOpen: true,

      // MIME type enforcement
      contentTypeOptions: { nosniff: true }
    };
  }

  /**
   * Rate limiting por tipo de operação
   */
  getRateLimiters() {
    return {
      // Rate limit para análise de IA (operação pesada)
      aiAnalysis: rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 20, // 20 análises por IP por 15 min
        message: {
          error: 'Muitas análises de IA. Tente novamente em 15 minutos.',
          code: 'RATE_LIMIT_AI_ANALYSIS'
        },
        standardHeaders: true,
        legacyHeaders: false,
      }),

      // Rate limit para geração de Excel
      excelGeneration: rateLimit({
        windowMs: 10 * 60 * 1000, // 10 minutos
        max: 10, // 10 gerações por IP por 10 min
        message: {
          error: 'Muitas gerações de planilhas. Tente novamente em 10 minutos.',
          code: 'RATE_LIMIT_EXCEL_GENERATION'
        },
        standardHeaders: true,
        legacyHeaders: false,
      }),

      // Rate limit geral para API
      general: rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 100, // 100 requests por IP por 15 min
        message: {
          error: 'Muitas requisições. Tente novamente em 15 minutos.',
          code: 'RATE_LIMIT_GENERAL'
        },
        standardHeaders: true,
        legacyHeaders: false,
      }),

      // Rate limit para autenticação
      auth: rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 5, // 5 tentativas de login por IP por 15 min
        message: {
          error: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
          code: 'RATE_LIMIT_AUTH'
        },
        standardHeaders: true,
        legacyHeaders: false,
      })
    };
  }

  /**
   * Validação de entrada robusta
   */
  getInputValidation() {
    return {
      // Sanitização de strings
      sanitizeString: (input, maxLength = 1000) => {
        if (typeof input !== 'string') return '';
        
        return input
          .trim()
          .slice(0, maxLength)
          .replace(/[<>]/g, '') // Remove tags HTML básicas
          .replace(/javascript:/gi, '') // Remove javascript:
          .replace(/data:/gi, ''); // Remove data:
      },

      // Validação de email
      isValidEmail: (email) => {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email) && email.length <= 254;
      },

      // Validação de senha segura
      isStrongPassword: (password) => {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasNonalphas = /\W/.test(password);
        
        return password.length >= minLength && 
               hasUpperCase && 
               hasLowerCase && 
               hasNumbers && 
               hasNonalphas;
      },

      // Validação de session ID
      isValidSessionId: (sessionId) => {
        const sessionRegex = /^[a-f0-9]{32}$/;
        return sessionRegex.test(sessionId);
      }
    };
  }

  /**
   * Funções de criptografia
   */
  getCryptoFunctions() {
    return {
      // Hash de senha
      hashPassword: async (password) => {
        const salt = await bcrypt.genSalt(this.bcryptRounds);
        return bcrypt.hash(password, salt);
      },

      // Verificar senha
      verifyPassword: async (password, hash) => {
        return bcrypt.compare(password, hash);
      },

      // Gerar token JWT
      generateToken: (payload, expiresIn = this.tokenExpiry) => {
        return jwt.sign(payload, this.jwtSecret, { 
          expiresIn,
          issuer: 'turbo-ia-enterprise',
          audience: 'turbo-ia-users'
        });
      },

      // Verificar token JWT
      verifyToken: (token) => {
        try {
          return jwt.verify(token, this.jwtSecret, {
            issuer: 'turbo-ia-enterprise',
            audience: 'turbo-ia-users'
          });
        } catch (error) {
          throw new Error('Token inválido');
        }
      },

      // Gerar ID de sessão seguro
      generateSessionId: () => {
        return crypto.randomBytes(16).toString('hex');
      },

      // Criptografar dados sensíveis
      encrypt: (text) => {
        const algorithm = 'aes-256-gcm';
        const key = crypto.scryptSync(this.jwtSecret, 'salt', 32);
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(algorithm, key);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return {
          encrypted,
          iv: iv.toString('hex'),
          tag: cipher.getAuthTag().toString('hex')
        };
      },

      // Descriptografar dados
      decrypt: (encryptedData) => {
        const algorithm = 'aes-256-gcm';
        const key = crypto.scryptSync(this.jwtSecret, 'salt', 32);
        const decipher = crypto.createDecipher(algorithm, key);
        
        decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'));
        
        let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
      }
    };
  }

  /**
   * Configurações de CORS seguras
   */
  getCORSConfig() {
    const allowedOrigins = process.env.ALLOWED_ORIGINS 
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['http://localhost:3000', 'http://localhost:3001'];

    return {
      origin: (origin, callback) => {
        // Permitir requests sem origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Não permitido pelo CORS'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: [
        'Origin',
        'X-Requested-With',
        'Content-Type',
        'Accept',
        'Authorization',
        'X-Session-ID'
      ],
      exposedHeaders: ['X-Total-Count'],
      maxAge: 86400 // 24 horas
    };
  }

  /**
   * Configurações de sessão segura
   */
  getSessionConfig() {
    return {
      secret: this.jwtSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production', // HTTPS apenas em produção
        httpOnly: true, // Previne acesso via JavaScript
        maxAge: 24 * 60 * 60 * 1000, // 24 horas
        sameSite: 'strict' // Proteção CSRF
      },
      name: 'turbo-ia-session' // Nome customizado do cookie
    };
  }
}

// Instância singleton
const securityConfig = new SecurityConfig();

module.exports = {
  SecurityConfig,
  helmet: securityConfig.getHelmetConfig(),
  rateLimiters: securityConfig.getRateLimiters(),
  inputValidation: securityConfig.getInputValidation(),
  crypto: securityConfig.getCryptoFunctions(),
  cors: securityConfig.getCORSConfig(),
  session: securityConfig.getSessionConfig()
}; 
