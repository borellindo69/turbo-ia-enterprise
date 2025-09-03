 
/**
 * Middleware de Rate Limiting Enterprise - Turbo.IA
 * Sistema inteligente de controle de taxa de requisições
 * Rate limiting específico para operações de IA e Excel
 */

const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { redis } = require('../../config/redis');
const { logger, performanceLogger } = require('../../config/logger');

class RateLimitMiddleware {
  constructor() {
    this.redisClient = redis;
    this.initializeStores();
    this.setupDynamicLimits();
  }

  /**
   * Inicializar stores Redis para diferentes tipos de limite
   */
  initializeStores() {
    // Store para operações de IA (mais restritivo)
    this.aiStore = new RedisStore({
      sendCommand: (...args) => this.redisClient.call(...args),
      prefix: 'rl:ai:'
    });

    // Store para geração de Excel
    this.excelStore = new RedisStore({
      sendCommand: (...args) => this.redisClient.call(...args),
      prefix: 'rl:excel:'
    });

    // Store para requisições gerais
    this.generalStore = new RedisStore({
      sendCommand: (...args) => this.redisClient.call(...args),
      prefix: 'rl:general:'
    });

    // Store para autenticação
    this.authStore = new RedisStore({
      sendCommand: (...args) => this.redisClient.call(...args),
      prefix: 'rl:auth:'
    });
  }

  /**
   * Configurar limites dinâmicos baseados em carga do sistema
   */
  setupDynamicLimits() {
    this.baseLimits = {
      ai: {
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 10, // 10 análises por IP
        premium: 25 // 25 para usuários premium
      },
      excel: {
        windowMs: 10 * 60 * 1000, // 10 minutos
        max: 15, // 15 gerações por IP
        premium: 40 // 40 para usuários premium
      },
      general: {
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 100, // 100 requisições por IP
        premium: 250 // 250 para usuários premium
      },
      auth: {
        windowMs: 15 * 60 * 1000, // 15 minutos
        max: 5, // 5 tentativas de login
        premium: 10 // 10 para usuários premium
      }
    };

    this.currentLoad = 'normal'; // normal, high, critical
    this.loadCheckInterval = 5 * 60 * 1000; // 5 minutos

    this.startLoadMonitoring();
  }

  /**
   * Monitorar carga do sistema e ajustar limites
   */
  startLoadMonitoring() {
    setInterval(async () => {
      try {
        const memoryUsage = process.memoryUsage();
        const heapUsedMB = memoryUsage.heapUsed / 1024 / 1024;
        const heapTotalMB = memoryUsage.heapTotal / 1024 / 1024;
        const cpuUsage = process.cpuUsage();

        // Determinar nível de carga
        let newLoad = 'normal';
        
        if (heapUsedMB > 400 || heapTotalMB > 512) {
          newLoad = 'high';
        }
        
        if (heapUsedMB > 600 || heapTotalMB > 768) {
          newLoad = 'critical';
        }

        if (newLoad !== this.currentLoad) {
          this.currentLoad = newLoad;
          
          performanceLogger.info('Nível de carga alterado', {
            previousLoad: this.currentLoad,
            newLoad,
            memoryUsage: {
              heapUsedMB: Math.round(heapUsedMB),
              heapTotalMB: Math.round(heapTotalMB)
            }
          });
        }

      } catch (error) {
        logger.error('Erro no monitoramento de carga:', error.message);
      }
    }, this.loadCheckInterval);
  }

  /**
   * Calcular limite baseado na carga atual
   */
  calculateLimit(baseLimit, userType = 'free') {
    const userMultiplier = userType === 'premium' ? 2.5 : 1;
    let loadMultiplier = 1;

    switch (this.currentLoad) {
      case 'high':
        loadMultiplier = 0.7; // Reduzir 30%
        break;
      case 'critical':
        loadMultiplier = 0.4; // Reduzir 60%
        break;
      default:
        loadMultiplier = 1;
    }

    return Math.max(1, Math.floor(baseLimit * userMultiplier * loadMultiplier));
  }

  /**
   * Função de chave personalizada para rate limiting
   */
  getKeyGenerator(type) {
    return (req) => {
      // Priorizar usuário autenticado, depois IP
      const userId = req.user?.userId;
      const ip = req.ip;
      const userAgent = req.get('User-Agent')?.substring(0, 50) || 'unknown';
      
      if (userId) {
        return `${type}:user:${userId}`;
      }
      
      // Para IPs, incluir parte do user agent para diferenciação
      const agentHash = Buffer.from(userAgent).toString('base64').substring(0, 10);
      return `${type}:ip:${ip}:${agentHash}`;
    };
  }

  /**
   * Handler customizado quando limite é excedido
   */
  createLimitHandler(operationType) {
    return (req, res) => {
      const resetTime = new Date(Date.now() + req.rateLimit.resetTime);
      
      logger.warn(`Rate limit excedido - ${operationType}`, {
        ip: req.ip,
        userId: req.user?.userId,
        limit: req.rateLimit.limit,
        remaining: req.rateLimit.remaining,
        resetTime: resetTime.toISOString(),
        userAgent: req.get('User-Agent')
      });

      res.status(429).json({
        success: false,
        error: `Muitas requisições de ${operationType}. Tente novamente mais tarde.`,
        code: `RATE_LIMIT_${operationType.toUpperCase()}`,
        details: {
          limit: req.rateLimit.limit,
          remaining: req.rateLimit.remaining,
          resetTime: resetTime.toISOString(),
          retryAfter: Math.round(req.rateLimit.resetTime / 1000)
        }
      });
    };
  }

  /**
   * Rate limiter para análises de IA
   */
  aiAnalysisLimit() {
    return rateLimit({
      store: this.aiStore,
      windowMs: this.baseLimits.ai.windowMs,
      max: (req) => {
        const userType = req.user?.subscription || 'free';
        const baseLimit = this.baseLimits.ai.max;
        return this.calculateLimit(baseLimit, userType);
      },
      keyGenerator: this.getKeyGenerator('ai'),
      handler: this.createLimitHandler('análise IA'),
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        // Pular rate limit para admins em desenvolvimento
        return process.env.NODE_ENV === 'development' && req.user?.role === 'admin';
      },
      onLimitReached: (req, res, options) => {
        performanceLogger.warn('Limite de IA atingido', {
          ip: req.ip,
          userId: req.user?.userId,
          limit: options.max,
          systemLoad: this.currentLoad
        });
      }
    });
  }

  /**
   * Rate limiter para geração de Excel
   */
  excelGenerationLimit() {
    return rateLimit({
      store: this.excelStore,
      windowMs: this.baseLimits.excel.windowMs,
      max: (req) => {
        const userType = req.user?.subscription || 'free';
        const baseLimit = this.baseLimits.excel.max;
        return this.calculateLimit(baseLimit, userType);
      },
      keyGenerator: this.getKeyGenerator('excel'),
      handler: this.createLimitHandler('geração Excel'),
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        return process.env.NODE_ENV === 'development' && req.user?.role === 'admin';
      }
    });
  }

  /**
   * Rate limiter geral para API
   */
  generalApiLimit() {
    return rateLimit({
      store: this.generalStore,
      windowMs: this.baseLimits.general.windowMs,
      max: (req) => {
        const userType = req.user?.subscription || 'free';
        const baseLimit = this.baseLimits.general.max;
        return this.calculateLimit(baseLimit, userType);
      },
      keyGenerator: this.getKeyGenerator('general'),
      handler: this.createLimitHandler('API geral'),
      standardHeaders: true,
      legacyHeaders: false,
      skip: (req) => {
        // Pular para endpoints públicos específicos
        const publicEndpoints = ['/api/health', '/api/status'];
        return publicEndpoints.includes(req.path);
      }
    });
  }

  /**
   * Rate limiter para autenticação
   */
  authenticationLimit() {
    return rateLimit({
      store: this.authStore,
      windowMs: this.baseLimits.auth.windowMs,
      max: this.baseLimits.auth.max,
      keyGenerator: this.getKeyGenerator('auth'),
      handler: (req, res) => {
        logger.warn('Muitas tentativas de autenticação', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.path
        });

        res.status(429).json({
          success: false,
          error: 'Muitas tentativas de login. Tente novamente em 15 minutos.',
          code: 'RATE_LIMIT_AUTH',
          details: {
            retryAfter: Math.round(this.baseLimits.auth.windowMs / 1000)
          }
        });
      },
      standardHeaders: true,
      legacyHeaders: false
    });
  }

  /**
   * Rate limiter progressivo (aumenta restrição com uso)
   */
  progressiveLimit(baseConfig) {
    return rateLimit({
      ...baseConfig,
      max: (req) => {
        const userKey = this.getKeyGenerator('progressive')(req);
        
        // Implementar lógica progressiva aqui
        // Por exemplo: reduzir limite baseado em uso recente
        
        return baseConfig.max;
      }
    });
  }

  /**
   * Middleware de bypass para usuários VIP
   */
  vipBypass() {
    return (req, res, next) => {
      if (req.user?.role === 'vip' || req.user?.subscription === 'enterprise') {
        req.skipRateLimit = true;
      }
      next();
    };
  }

  /**
   * Estatísticas de rate limiting
   */
  async getRateLimitStats() {
    try {
      const stats = {
        currentLoad: this.currentLoad,
        limits: this.baseLimits,
        timestamp: new Date().toISOString()
      };

      // Adicionar estatísticas do Redis se disponível
      if (this.redisClient && typeof this.redisClient.info === 'function') {
        const redisInfo = await this.redisClient.info('stats');
        stats.redis = redisInfo;
      }

      return stats;
    } catch (error) {
      logger.error('Erro ao obter estatísticas de rate limit:', error.message);
      return null;
    }
  }

  /**
   * Limpar dados de rate limiting expirados
   */
  async cleanup() {
    try {
      const patterns = ['rl:ai:*', 'rl:excel:*', 'rl:general:*', 'rl:auth:*'];
      
      for (const pattern of patterns) {
        const keys = await this.redisClient.keys(pattern);
        const expiredKeys = [];
        
        for (const key of keys) {
          const ttl = await this.redisClient.ttl(key);
          if (ttl <= 0) {
            expiredKeys.push(key);
          }
        }
        
        if (expiredKeys.length > 0) {
          await this.redisClient.del(...expiredKeys);
        }
      }
      
      logger.info('Limpeza de rate limiting concluída');
    } catch (error) {
      logger.error('Erro na limpeza de rate limiting:', error.message);
    }
  }
}

// Instância singleton
const rateLimitMiddleware = new RateLimitMiddleware();

// Limpeza automática a cada hora
setInterval(() => {
  rateLimitMiddleware.cleanup();
}, 60 * 60 * 1000);

module.exports = {
  RateLimitMiddleware,
  
  // Rate limiters específicos
  aiAnalysisLimit: rateLimitMiddleware.aiAnalysisLimit(),
  excelGenerationLimit: rateLimitMiddleware.excelGenerationLimit(),
  generalApiLimit: rateLimitMiddleware.generalApiLimit(),
  authenticationLimit: rateLimitMiddleware.authenticationLimit(),
  
  // Middlewares auxiliares
  vipBypass: rateLimitMiddleware.vipBypass(),
  
  // Funções utilitárias
  getRateLimitStats: () => rateLimitMiddleware.getRateLimitStats(),
  cleanup: () => rateLimitMiddleware.cleanup()
};