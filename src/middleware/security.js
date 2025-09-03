 
/**
 * Middleware de Segurança Enterprise - Turbo.IA
 * Sistema completo de autenticação, autorização e proteção
 * Segurança robusta para ambiente corporativo
 */

const jwt = require('jsonwebtoken');
const { crypto, rateLimiters } = require('../../config/security');
const { logger, securityLogger } = require('../../config/logger');
const { cache } = require('../../config/redis');

class SecurityMiddleware {
  constructor() {
    this.tokenBlacklist = new Set(); // Lista de tokens revogados
    this.suspiciousIPs = new Map(); // IPs com atividade suspeita
    this.maxSuspiciousAttempts = 10;
    this.suspiciousWindowMs = 15 * 60 * 1000; // 15 minutos
  }

  /**
   * Middleware de autenticação JWT
   */
  authenticateToken() {
    return async (req, res, next) => {
      try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
          return res.status(401).json({
            success: false,
            error: 'Token de acesso requerido.',
            code: 'MISSING_TOKEN'
          });
        }

        // Verificar se token está na blacklist
        if (this.tokenBlacklist.has(token)) {
          securityLogger.warn('Tentativa de uso de token revogado', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            token: token.substring(0, 20) + '...'
          });

          return res.status(401).json({
            success: false,
            error: 'Token revogado.',
            code: 'REVOKED_TOKEN'
          });
        }

        // Verificar token no cache primeiro
        const cachedUser = await cache.getUserSession(token);
        if (cachedUser) {
          req.user = cachedUser;
          return next();
        }

        // Verificar e decodificar token
        const decoded = crypto.verifyToken(token);
        
        // Verificar se é um refresh token sendo usado indevidamente
        if (decoded.type === 'refresh') {
          return res.status(401).json({
            success: false,
            error: 'Token de refresh não pode ser usado para autenticação.',
            code: 'INVALID_TOKEN_TYPE'
          });
        }

        // Cachear informações do usuário
        await cache.cacheUserSession(token, decoded);
        
        req.user = decoded;
        req.token = token;

        securityLogger.info('Autenticação bem-sucedida', {
          userId: decoded.userId,
          ip: req.ip,
          endpoint: req.path
        });

        next();
      } catch (error) {
        securityLogger.warn('Falha na autenticação', {
          error: error.message,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path
        });

        return res.status(401).json({
          success: false,
          error: 'Token inválido.',
          code: 'INVALID_TOKEN'
        });
      }
    };
  }

  /**
   * Middleware de autorização baseado em roles
   */
  authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            success: false,
            error: 'Usuário não autenticado.',
            code: 'NOT_AUTHENTICATED'
          });
        }

        const userRole = req.user.role || 'user';
        
        if (!allowedRoles.includes(userRole)) {
          securityLogger.warn('Tentativa de acesso não autorizado', {
            userId: req.user.userId,
            userRole: userRole,
            requiredRoles: allowedRoles,
            endpoint: req.path,
            ip: req.ip
          });

          return res.status(403).json({
            success: false,
            error: 'Acesso negado. Permissões insuficientes.',
            code: 'INSUFFICIENT_PERMISSIONS'
          });
        }

        next();
      } catch (error) {
        logger.error('Erro na autorização:', error.message);
        return res.status(500).json({
          success: false,
          error: 'Erro interno na autorização.',
          code: 'AUTHORIZATION_ERROR'
        });
      }
    };
  }

  /**
   * Middleware de detecção de atividade suspeita
   */
  detectSuspiciousActivity() {
    return (req, res, next) => {
      try {
        const clientIP = req.ip;
        const userAgent = req.get('User-Agent');
        const now = Date.now();

        // Verificar se IP está sendo monitorado
        if (this.suspiciousIPs.has(clientIP)) {
          const attempts = this.suspiciousIPs.get(clientIP);
          
          // Limpar tentativas antigas
          const recentAttempts = attempts.filter(
            timestamp => now - timestamp < this.suspiciousWindowMs
          );

          if (recentAttempts.length >= this.maxSuspiciousAttempts) {
            securityLogger.warn('IP bloqueado por atividade suspeita', {
              ip: clientIP,
              attempts: recentAttempts.length,
              userAgent
            });

            return res.status(429).json({
              success: false,
              error: 'Muitas tentativas suspeitas. IP temporariamente bloqueado.',
              code: 'SUSPICIOUS_ACTIVITY_BLOCKED'
            });
          }

          this.suspiciousIPs.set(clientIP, recentAttempts);
        }

        // Detectar padrões suspeitos
        const suspiciousPatterns = [
          // User agents suspeitos
          /bot|crawler|spider/i.test(userAgent) && !req.path.includes('/api/public'),
          
          // Tentativas de acesso a endpoints sensíveis
          req.path.includes('/admin') && (!req.user || req.user.role !== 'admin'),
          
          // Muitos parâmetros na query string
          Object.keys(req.query).length > 20,
          
          // Headers suspeitos
          req.headers['x-forwarded-for']?.split(',').length > 5
        ];

        if (suspiciousPatterns.some(pattern => pattern)) {
          this.recordSuspiciousAttempt(clientIP);
          
          securityLogger.warn('Atividade suspeita detectada', {
            ip: clientIP,
            userAgent,
            endpoint: req.path,
            query: req.query,
            userId: req.user?.userId
          });
        }

        next();
      } catch (error) {
        logger.error('Erro na detecção de atividade suspeita:', error.message);
        next(); // Continuar mesmo com erro para não bloquear o sistema
      }
    };
  }

  /**
   * Registrar tentativa suspeita
   */
  recordSuspiciousAttempt(ip) {
    const now = Date.now();
    
    if (!this.suspiciousIPs.has(ip)) {
      this.suspiciousIPs.set(ip, []);
    }
    
    const attempts = this.suspiciousIPs.get(ip);
    attempts.push(now);
    
    // Manter apenas tentativas recentes
    const recentAttempts = attempts.filter(
      timestamp => now - timestamp < this.suspiciousWindowMs
    );
    
    this.suspiciousIPs.set(ip, recentAttempts);
  }

  /**
   * Middleware de rate limiting inteligente
   */
  intelligentRateLimit() {
    return (req, res, next) => {
      const limitType = req.rateLimitType || 'general';
      const limiter = rateLimiters[limitType] || rateLimiters.general;
      
      return limiter(req, res, (err) => {
        if (err) {
          this.recordSuspiciousAttempt(req.ip);
          
          securityLogger.warn('Rate limit excedido', {
            ip: req.ip,
            limitType,
            endpoint: req.path,
            userAgent: req.get('User-Agent')
          });
        }
        next(err);
      });
    };
  }

  /**
   * Middleware de validação de origem
   */
  validateOrigin() {
    return (req, res, next) => {
      try {
        const origin = req.get('Origin');
        const referer = req.get('Referer');
        
        // Para requests de API, validar origem
        if (req.path.startsWith('/api/')) {
          const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || 
                                ['http://localhost:3000', 'http://localhost:3001'];
          
          if (origin && !allowedOrigins.includes(origin)) {
            securityLogger.warn('Origem não permitida', {
              origin,
              referer,
              ip: req.ip,
              endpoint: req.path
            });

            return res.status(403).json({
              success: false,
              error: 'Origem não permitida.',
              code: 'INVALID_ORIGIN'
            });
          }
        }

        next();
      } catch (error) {
        logger.error('Erro na validação de origem:', error.message);
        next();
      }
    };
  }

  /**
   * Middleware de proteção CSRF
   */
  protectCSRF() {
    return (req, res, next) => {
      try {
        // Para métodos que modificam dados
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
          const csrfToken = req.headers['x-csrf-token'] || req.body._csrf;
          const sessionToken = req.headers['x-session-id'];
          
          if (!csrfToken && !sessionToken) {
            securityLogger.warn('Tentativa de request sem proteção CSRF', {
              ip: req.ip,
              method: req.method,
              endpoint: req.path,
              userAgent: req.get('User-Agent')
            });

            return res.status(403).json({
              success: false,
              error: 'Token CSRF requerido.',
              code: 'CSRF_TOKEN_REQUIRED'
            });
          }
        }

        next();
      } catch (error) {
        logger.error('Erro na proteção CSRF:', error.message);
        next();
      }
    };
  }

  /**
   * Middleware de logout/revogação de token
   */
  revokeToken() {
    return async (req, res, next) => {
      try {
        const token = req.token;
        
        if (token) {
          // Adicionar token à blacklist
          this.tokenBlacklist.add(token);
          
          // Remover do cache
          await cache.invalidatePattern(`user_session:${token}`);
          
          securityLogger.info('Token revogado', {
            userId: req.user?.userId,
            ip: req.ip
          });
        }

        next();
      } catch (error) {
        logger.error('Erro ao revogar token:', error.message);
        next();
      }
    };
  }

  /**
   * Middleware de logging de segurança
   */
  logSecurityEvents() {
    return (req, res, next) => {
      // Log de eventos importantes
      const sensitiveEndpoints = ['/api/auth', '/api/admin', '/api/ai/analyze'];
      
      if (sensitiveEndpoints.some(endpoint => req.path.startsWith(endpoint))) {
        securityLogger.info('Acesso a endpoint sensível', {
          endpoint: req.path,
          method: req.method,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          userId: req.user?.userId,
          timestamp: new Date().toISOString()
        });
      }

      next();
    };
  }

  /**
   * Limpeza periódica de dados de segurança
   */
  cleanupSecurityData() {
    setInterval(() => {
      try {
        const now = Date.now();
        
        // Limpar IPs suspeitos antigos
        for (const [ip, attempts] of this.suspiciousIPs.entries()) {
          const recentAttempts = attempts.filter(
            timestamp => now - timestamp < this.suspiciousWindowMs
          );
          
          if (recentAttempts.length === 0) {
            this.suspiciousIPs.delete(ip);
          } else {
            this.suspiciousIPs.set(ip, recentAttempts);
          }
        }

        // Limpar blacklist de tokens (manter por 24h)
        // Nota: Em produção, isso deveria ser persistido em banco
        
        logger.info('Limpeza de dados de segurança concluída', {
          suspiciousIPs: this.suspiciousIPs.size,
          blacklistedTokens: this.tokenBlacklist.size
        });
        
      } catch (error) {
        logger.error('Erro na limpeza de dados de segurança:', error.message);
      }
    }, 60 * 60 * 1000); // A cada hora
  }
}

// Instância singleton
const securityMiddleware = new SecurityMiddleware();

// Iniciar limpeza automática
securityMiddleware.cleanupSecurityData();

module.exports = {
  SecurityMiddleware,
  
  // Middlewares prontos para uso
  authenticateToken: securityMiddleware.authenticateToken(),
  authorizeRoles: (...roles) => securityMiddleware.authorizeRoles(...roles),
  detectSuspiciousActivity: securityMiddleware.detectSuspiciousActivity(),
  intelligentRateLimit: securityMiddleware.intelligentRateLimit(),
  validateOrigin: securityMiddleware.validateOrigin(),
  protectCSRF: securityMiddleware.protectCSRF(),
  revokeToken: securityMiddleware.revokeToken(),
  logSecurityEvents: securityMiddleware.logSecurityEvents()
};