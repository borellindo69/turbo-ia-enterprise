/**
 * Configuração Redis Enterprise - Turbo.IA
 * Sistema de cache inteligente para otimização de performance
 * Cache especializado para 60+ padrões empresariais
 */

const Redis = require('ioredis');
const crypto = require('crypto');
const { logger } = require('./logger');

class RedisConfig {
  constructor() {
    this.redis = null;
    this.isConnected = false;
    this.retryAttempts = 0;
    this.maxRetryAttempts = 5;
    this.retryDelay = 2000;
    
    // TTL padrão para diferentes tipos de cache (em segundos)
    this.cacheTTL = {
      aiAnalysis: 3600,      // 1 hora - análises de IA
      excelTemplates: 7200,  // 2 horas - templates Excel
      userSessions: 86400,   // 24 horas - sessões de usuário
      patterns: 21600,       // 6 horas - padrões empresariais
      performance: 1800,     // 30 minutos - métricas de performance
      shortTerm: 300         // 5 minutos - cache temporário
    };
  }

  /**
   * Configurações de conexão Redis
   */
  getConnectionConfig() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
    
    return {
      // Configurações de conexão
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: 3,
      connectTimeout: 60000,
      commandTimeout: 5000,
      lazyConnect: true,
      
      // Pool de conexões
      family: 4,
      keepAlive: true,
      
      // Configurações de retry
      retryDelayOnClusterDown: 300,
      retryDelayOnFailover: 100,
      maxRetriesPerRequest: null,
      
      // Configurações de performance
      enableAutoPipelining: true,
      maxMemoryPolicy: 'allkeys-lru',
      
      // Configurações de segurança
      password: process.env.REDIS_PASSWORD,
      db: process.env.REDIS_DB || 0
    };
  }

  /**
   * Conectar ao Redis com retry automático
   */
  async connect() {
    try {
      const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';
      const config = this.getConnectionConfig();

      logger.info('Conectando ao Redis...', { url: redisUrl.replace(/:[^:@]*@/, ':***@') });

      this.redis = new Redis(redisUrl, config);

      // Configurar eventos
      this.setupEventListeners();

      // Testar conexão
      await this.redis.ping();
      
      this.isConnected = true;
      this.retryAttempts = 0;
      
      logger.info('Redis conectado com sucesso');
      
      return true;

    } catch (error) {
      this.isConnected = false;
      
      logger.error('Erro ao conectar Redis:', {
        error: error.message,
        attempt: this.retryAttempts + 1
      });

      // Retry automático
      if (this.retryAttempts < this.maxRetryAttempts) {
        this.retryAttempts++;
        logger.info(`Tentando reconectar Redis em ${this.retryDelay / 1000} segundos...`);
        
        setTimeout(() => {
          this.connect();
        }, this.retryDelay);
        
        return false;
      } else {
        logger.error('Máximo de tentativas de conexão Redis excedido');
        return false;
      }
    }
  }

  /**
   * Configurar listeners de eventos
   */
  setupEventListeners() {
    this.redis.on('connect', () => {
      logger.info('Redis conectado');
      this.isConnected = true;
    });

    this.redis.on('ready', () => {
      logger.info('Redis pronto para uso');
    });

    this.redis.on('error', (error) => {
      logger.error('Erro Redis:', error.message);
      this.isConnected = false;
    });

    this.redis.on('close', () => {
      logger.warn('Conexão Redis fechada');
      this.isConnected = false;
    });

    this.redis.on('reconnecting', () => {
      logger.info('Reconectando ao Redis...');
    });
  }

  /**
   * Gerar chave de cache baseada em conteúdo
   */
  generateCacheKey(prefix, data) {
    const content = typeof data === 'string' ? data : JSON.stringify(data);
    const hash = crypto.createHash('md5').update(content).digest('hex');
    return `${prefix}:${hash}`;
  }

  /**
   * Funções de cache especializadas
   */
  getCacheFunctions() {
    return {
      /**
       * Cache para análises de IA
       */
      cacheAIAnalysis: async (userInput, analysis) => {
        if (!this.isConnected) return false;
        
        try {
          const key = this.generateCacheKey('ai_analysis', userInput);
          const value = JSON.stringify({
            analysis,
            timestamp: new Date().toISOString(),
            version: '1.0'
          });
          
          await this.redis.setex(key, this.cacheTTL.aiAnalysis, value);
          
          logger.info('Análise IA armazenada em cache', { key: key.substring(0, 20) + '...' });
          return true;
        } catch (error) {
          logger.error('Erro ao cachear análise IA:', error.message);
          return false;
        }
      },

      /**
       * Recuperar análise de IA do cache
       */
      getAIAnalysis: async (userInput) => {
        if (!this.isConnected) return null;
        
        try {
          const key = this.generateCacheKey('ai_analysis', userInput);
          const cached = await this.redis.get(key);
          
          if (cached) {
            const data = JSON.parse(cached);
            logger.info('Análise IA recuperada do cache', { key: key.substring(0, 20) + '...' });
            return data.analysis;
          }
          
          return null;
        } catch (error) {
          logger.error('Erro ao recuperar análise IA do cache:', error.message);
          return null;
        }
      },

      /**
       * Cache para templates Excel
       */
      cacheExcelTemplate: async (patternType, template) => {
        if (!this.isConnected) return false;
        
        try {
          const key = `excel_template:${patternType}`;
          const value = JSON.stringify({
            template,
            timestamp: new Date().toISOString()
          });
          
          await this.redis.setex(key, this.cacheTTL.excelTemplates, value);
          return true;
        } catch (error) {
          logger.error('Erro ao cachear template Excel:', error.message);
          return false;
        }
      },

      /**
       * Recuperar template Excel do cache
       */
      getExcelTemplate: async (patternType) => {
        if (!this.isConnected) return null;
        
        try {
          const key = `excel_template:${patternType}`;
          const cached = await this.redis.get(key);
          
          if (cached) {
            const data = JSON.parse(cached);
            return data.template;
          }
          
          return null;
        } catch (error) {
          logger.error('Erro ao recuperar template Excel do cache:', error.message);
          return null;
        }
      },

      /**
       * Cache para sessões de usuário
       */
      cacheUserSession: async (sessionId, sessionData) => {
        if (!this.isConnected) return false;
        
        try {
          const key = `user_session:${sessionId}`;
          const value = JSON.stringify(sessionData);
          
          await this.redis.setex(key, this.cacheTTL.userSessions, value);
          return true;
        } catch (error) {
          logger.error('Erro ao cachear sessão:', error.message);
          return false;
        }
      },

      /**
       * Recuperar sessão de usuário
       */
      getUserSession: async (sessionId) => {
        if (!this.isConnected) return null;
        
        try {
          const key = `user_session:${sessionId}`;
          const cached = await this.redis.get(key);
          
          if (cached) {
            return JSON.parse(cached);
          }
          
          return null;
        } catch (error) {
          logger.error('Erro ao recuperar sessão:', error.message);
          return null;
        }
      },

      /**
       * Invalidar cache por padrão
       */
      invalidatePattern: async (pattern) => {
        if (!this.isConnected) return false;
        
        try {
          const keys = await this.redis.keys(pattern);
          if (keys.length > 0) {
            await this.redis.del(...keys);
            logger.info(`Cache invalidado: ${keys.length} chaves removidas`);
          }
          return true;
        } catch (error) {
          logger.error('Erro ao invalidar cache:', error.message);
          return false;
        }
      },

      /**
       * Estatísticas do cache
       */
      getCacheStats: async () => {
        if (!this.isConnected) return null;
        
        try {
          const info = await this.redis.info('memory');
          const keyspace = await this.redis.info('keyspace');
          
          return {
            memory: info,
            keyspace: keyspace,
            connected: this.isConnected,
            timestamp: new Date().toISOString()
          };
        } catch (error) {
          logger.error('Erro ao obter estatísticas do cache:', error.message);
          return null;
        }
      },

      /**
       * Limpeza de cache expirado
       */
      cleanupExpiredCache: async () => {
        if (!this.isConnected) return false;
        
        try {
          // Redis limpa automaticamente chaves expiradas,
          // mas podemos forçar uma limpeza manual se necessário
          const info = await this.redis.info('stats');
          logger.info('Limpeza de cache executada', { stats: info });
          return true;
        } catch (error) {
          logger.error('Erro na limpeza de cache:', error.message);
          return false;
        }
      }
    };
  }

  /**
   * Desconectar do Redis
   */
  async disconnect() {
    if (this.redis) {
      await this.redis.quit();
      this.isConnected = false;
      logger.info('Redis desconectado');
    }
  }

  /**
   * Status da conexão
   */
  getStatus() {
    return {
      connected: this.isConnected,
      retryAttempts: this.retryAttempts,
      cacheTTL: this.cacheTTL
    };
  }
}

// Instância singleton
const redisConfig = new RedisConfig();

module.exports = {
  RedisConfig,
  connect: () => redisConfig.connect(),
  disconnect: () => redisConfig.disconnect(),
  getStatus: () => redisConfig.getStatus(),
  cache: redisConfig.getCacheFunctions(),
  isConnected: () => redisConfig.isConnected
}; 
