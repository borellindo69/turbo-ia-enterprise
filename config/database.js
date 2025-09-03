/**
 * Configuração Enterprise de Banco de Dados
 * Sistema robusto para suportar 60+ padrões de uso
 * Configurações otimizadas para escala empresarial
 */

const mongoose = require('mongoose');
const winston = require('winston');

class DatabaseConfig {
  constructor() {
    this.connectionState = {
      connected: false,
      connecting: false,
      disconnected: true
    };
    
    this.retryAttempts = 0;
    this.maxRetryAttempts = 5;
    this.retryDelay = 5000; // 5 segundos
  }

  /**
   * Configurações de conexão enterprise
   * Otimizado para performance e confiabilidade
   */
  getConnectionConfig() {
    return {
      // Configurações de performance
      maxPoolSize: 50, // Máximo de conexões simultâneas
      minPoolSize: 5,  // Mínimo de conexões ativas
      maxIdleTimeMS: 30000, // Timeout de conexão idle
      serverSelectionTimeoutMS: 5000, // Timeout de seleção de servidor
      socketTimeoutMS: 45000, // Timeout de socket
      
      // Configurações de confiabilidade
      retryWrites: true,
      retryReads: true,
      readPreference: 'primary',
      
      // Configurações de segurança
      authSource: 'admin',
      ssl: process.env.NODE_ENV === 'production',
      
      // Configurações de monitoramento
      heartbeatFrequencyMS: 10000,
      serverMonitoringMode: 'auto'
    };
  }

  /**
   * String de conexão baseada no ambiente
   */
  getConnectionString() {
    const env = process.env.NODE_ENV || 'development';
    
    switch (env) {
      case 'production':
        return process.env.MONGODB_PRODUCTION_URL || 'mongodb://localhost:27017/turbo_ia_production';
      
      case 'test':
        return process.env.MONGODB_TEST_URL || 'mongodb://localhost:27017/turbo_ia_test';
      
      default:
        return process.env.MONGODB_URL || 'mongodb://localhost:27017/turbo_ia_development';
    }
  }

  /**
   * Conectar ao banco com retry automático
   */
  async connect() {
    if (this.connectionState.connected || this.connectionState.connecting) {
      return true;
    }

    this.connectionState.connecting = true;
    this.connectionState.disconnected = false;

    try {
      const connectionString = this.getConnectionString();
      const config = this.getConnectionConfig();

      winston.info('Conectando ao banco de dados...', {
        database: connectionString.split('/').pop(),
        environment: process.env.NODE_ENV || 'development'
      });

      await mongoose.connect(connectionString, config);

      this.connectionState.connected = true;
      this.connectionState.connecting = false;
      this.retryAttempts = 0;

      winston.info('Banco de dados conectado com sucesso', {
        database: mongoose.connection.name,
        host: mongoose.connection.host,
        port: mongoose.connection.port
      });

      // Configurar eventos de monitoramento
      this.setupEventListeners();

      return true;

    } catch (error) {
      this.connectionState.connecting = false;
      this.connectionState.disconnected = true;

      winston.error('Erro ao conectar banco de dados:', {
        error: error.message,
        attempt: this.retryAttempts + 1,
        maxAttempts: this.maxRetryAttempts
      });

      // Retry automático em caso de falha
      if (this.retryAttempts < this.maxRetryAttempts) {
        this.retryAttempts++;
        winston.info(`Tentando reconexão em ${this.retryDelay / 1000} segundos...`);
        
        setTimeout(() => {
          this.connect();
        }, this.retryDelay);
        
        return false;
      } else {
        winston.error('Máximo de tentativas de conexão excedido');
        throw error;
      }
    }
  }

  /**
   * Configurar listeners de eventos para monitoramento
   */
  setupEventListeners() {
    const db = mongoose.connection;

    // Evento de desconexão
    db.on('disconnected', () => {
      winston.warn('Banco de dados desconectado');
      this.connectionState.connected = false;
      this.connectionState.disconnected = true;
      
      // Tentar reconectar automaticamente
      if (this.retryAttempts < this.maxRetryAttempts) {
        setTimeout(() => {
          this.connect();
        }, this.retryDelay);
      }
    });

    // Evento de erro
    db.on('error', (error) => {
      winston.error('Erro no banco de dados:', {
        error: error.message,
        code: error.code
      });
    });

    // Evento de reconexão
    db.on('reconnected', () => {
      winston.info('Banco de dados reconectado');
      this.connectionState.connected = true;
      this.connectionState.disconnected = false;
      this.retryAttempts = 0;
    });

    // Graceful shutdown
    process.on('SIGINT', async () => {
      winston.info('Fechando conexão com banco de dados...');
      await this.disconnect();
      process.exit(0);
    });
  }

  /**
   * Desconectar do banco
   */
  async disconnect() {
    try {
      await mongoose.connection.close();
      this.connectionState.connected = false;
      this.connectionState.disconnected = true;
      winston.info('Banco de dados desconectado');
    } catch (error) {
      winston.error('Erro ao desconectar banco:', error.message);
    }
  }

  /**
   * Verificar status da conexão
   */
  isConnected() {
    return this.connectionState.connected && mongoose.connection.readyState === 1;
  }

  /**
   * Obter informações de status
   */
  getStatus() {
    return {
      connected: this.connectionState.connected,
      connecting: this.connectionState.connecting,
      disconnected: this.connectionState.disconnected,
      readyState: mongoose.connection.readyState,
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      name: mongoose.connection.name,
      retryAttempts: this.retryAttempts
    };
  }

  /**
   * Configurações específicas para padrões enterprise
   * Otimizações para suportar 60+ padrões de uso simultaneamente
   */
  configureForEnterprisePatterns() {
    // Configurar timeouts específicos para operações pesadas
    mongoose.set('bufferMaxEntries', 0);
    mongoose.set('bufferCommands', false);
    
    // Configurar strictQuery para validação rigorosa
    mongoose.set('strictQuery', true);
    
    // Configurar debug apenas em desenvolvimento
    if (process.env.NODE_ENV === 'development') {
      mongoose.set('debug', true);
    }
  }
}

// Instância singleton para uso global
const databaseConfig = new DatabaseConfig();

module.exports = {
  DatabaseConfig,
  connect: () => databaseConfig.connect(),
  disconnect: () => databaseConfig.disconnect(),
  isConnected: () => databaseConfig.isConnected(),
  getStatus: () => databaseConfig.getStatus(),
  configureForEnterprisePatterns: () => databaseConfig.configureForEnterprisePatterns()
}; 
