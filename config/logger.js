/**
 * Sistema de Logs Enterprise - Turbo.IA
 * Logging profissional para monitoramento e debugging
 * Suporte completo para ambiente enterprise e 60+ padrões
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

class LoggerConfig {
  constructor() {
    this.createLogDirectories();
    this.setupLogRotation();
  }

  /**
   * Criar diretórios de logs se não existirem
   */
  createLogDirectories() {
    const logDirs = ['logs', 'logs/error', 'logs/combined', 'logs/access'];
    
    logDirs.forEach(dir => {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    });
  }

  /**
   * Configurar rotação de logs para ambiente enterprise
   */
  setupLogRotation() {
    this.logRotation = {
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d' // Manter logs por 14 dias
    };
  }

  /**
   * Formato customizado para logs enterprise
   */
  getLogFormat() {
    return winston.format.combine(
      winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss'
      }),
      winston.format.errors({ stack: true }),
      winston.format.printf(({ level, message, timestamp, ...metadata }) => {
        let msg = `${timestamp} [${level.toUpperCase()}]: ${message}`;
        
        // Adicionar metadata se existir
        if (Object.keys(metadata).length > 0) {
          msg += ` | ${JSON.stringify(metadata)}`;
        }
        
        return msg;
      })
    );
  }

  /**
   * Formato JSON para análise automatizada
   */
  getJSONFormat() {
    return winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json()
    );
  }

  /**
   * Transportes para diferentes tipos de log
   */
  getTransports() {
    const transports = [];

    // Console para desenvolvimento
    if (process.env.NODE_ENV !== 'production') {
      transports.push(
        new winston.transports.Console({
          format: winston.format.combine(
            winston.format.colorize(),
            this.getLogFormat()
          )
        })
      );
    }

    // Arquivo para erros críticos
    transports.push(
      new winston.transports.File({
        filename: 'logs/error/error.log',
        level: 'error',
        format: this.getJSONFormat(),
        maxsize: 5242880, // 5MB
        maxFiles: 5
      })
    );

    // Arquivo para todos os logs
    transports.push(
      new winston.transports.File({
        filename: 'logs/combined/combined.log',
        format: this.getJSONFormat(),
        maxsize: 5242880, // 5MB
        maxFiles: 5
      })
    );

    // Arquivo para logs de acesso/API
    transports.push(
      new winston.transports.File({
        filename: 'logs/access/access.log',
        level: 'info',
        format: this.getJSONFormat(),
        maxsize: 5242880, // 5MB
        maxFiles: 5
      })
    );

    return transports;
  }

  /**
   * Configuração de níveis enterprise
   */
  getLevels() {
    return {
      levels: {
        error: 0,
        warn: 1,
        info: 2,
        http: 3,
        verbose: 4,
        debug: 5,
        silly: 6
      },
      colors: {
        error: 'red',
        warn: 'yellow',
        info: 'green',
        http: 'magenta',
        verbose: 'grey',
        debug: 'blue',
        silly: 'cyan'
      }
    };
  }

  /**
   * Criar logger principal
   */
  createLogger() {
    const levels = this.getLevels();
    
    winston.addColors(levels.colors);

    return winston.createLogger({
      level: process.env.LOG_LEVEL || 'info',
      levels: levels.levels,
      format: this.getLogFormat(),
      transports: this.getTransports(),
      exitOnError: false,

      // Tratamento de exceções não capturadas
      exceptionHandlers: [
        new winston.transports.File({
          filename: 'logs/error/exceptions.log',
          format: this.getJSONFormat()
        })
      ],

      // Tratamento de promises rejeitadas
      rejectionHandlers: [
        new winston.transports.File({
          filename: 'logs/error/rejections.log',
          format: this.getJSONFormat()
        })
      ]
    });
  }

  /**
   * Logger específico para IA Operations
   */
  createAILogger() {
    return winston.createLogger({
      level: 'info',
      format: this.getJSONFormat(),
      transports: [
        new winston.transports.File({
          filename: 'logs/ai/ai-operations.log',
          maxsize: 5242880,
          maxFiles: 5
        })
      ]
    });
  }

  /**
   * Logger específico para geração de Excel
   */
  createExcelLogger() {
    return winston.createLogger({
      level: 'info',
      format: this.getJSONFormat(),
      transports: [
        new winston.transports.File({
          filename: 'logs/excel/excel-generation.log',
          maxsize: 5242880,
          maxFiles: 5
        })
      ]
    });
  }

  /**
   * Logger para métricas de performance
   */
  createPerformanceLogger() {
    return winston.createLogger({
      level: 'info',
      format: this.getJSONFormat(),
      transports: [
        new winston.transports.File({
          filename: 'logs/performance/performance.log',
          maxsize: 5242880,
          maxFiles: 5
        })
      ]
    });
  }

  /**
   * Logger para auditoria de segurança
   */
  createSecurityLogger() {
    return winston.createLogger({
      level: 'info',
      format: this.getJSONFormat(),
      transports: [
        new winston.transports.File({
          filename: 'logs/security/security.log',
          maxsize: 5242880,
          maxFiles: 5
        })
      ]
    });
  }
}

// Instanciar configuração
const loggerConfig = new LoggerConfig();

// Criar loggers especializados
const logger = loggerConfig.createLogger();
const aiLogger = loggerConfig.createAILogger();
const excelLogger = loggerConfig.createExcelLogger();
const performanceLogger = loggerConfig.createPerformanceLogger();
const securityLogger = loggerConfig.createSecurityLogger();

/**
 * Funções utilitárias para logging enterprise
 */
const logUtils = {
  /**
   * Log de operação de IA
   */
  logAIOperation: (operation, data, duration) => {
    aiLogger.info('AI Operation', {
      operation,
      data,
      duration,
      timestamp: new Date().toISOString()
    });
  },

  /**
   * Log de geração de Excel
   */
  logExcelGeneration: (patternType, userId, success, duration) => {
    excelLogger.info('Excel Generation', {
      patternType,
      userId,
      success,
      duration,
      timestamp: new Date().toISOString()
    });
  },

  /**
   * Log de performance
   */
  logPerformance: (operation, duration, memoryUsage) => {
    performanceLogger.info('Performance Metric', {
      operation,
      duration,
      memoryUsage,
      timestamp: new Date().toISOString()
    });
  },

  /**
   * Log de segurança
   */
  logSecurity: (event, userId, ip, details) => {
    securityLogger.warn('Security Event', {
      event,
      userId,
      ip,
      details,
      timestamp: new Date().toISOString()
    });
  },

  /**
   * Log de erro crítico
   */
  logCriticalError: (error, context) => {
    logger.error('Critical Error', {
      error: error.message,
      stack: error.stack,
      context,
      timestamp: new Date().toISOString()
    });
  }
};

module.exports = {
  logger,
  aiLogger,
  excelLogger,
  performanceLogger,
  securityLogger,
  logUtils,
  LoggerConfig
}; 
