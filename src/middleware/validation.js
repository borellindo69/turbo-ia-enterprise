/**
 * Middleware de Validação Enterprise - Turbo.IA
 * Sistema robusto de validação para proteger contra dados inválidos
 * Validação especializada para 60+ padrões empresariais
 */

const Joi = require('joi');
const { celebrate, Segments, errors } = require('celebrate');
const { logger } = require('../../config/logger');
const { inputValidation } = require('../../config/security');

class ValidationMiddleware {
  constructor() {
    this.maxInputLength = 10000; // 10KB max por input
    this.maxFileSize = 50 * 1024 * 1024; // 50MB max para arquivos
    this.allowedFileTypes = [
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
      'application/vnd.ms-excel', // .xls
      'text/csv', // .csv
      'application/json', // .json
      'text/plain' // .txt
    ];
  }

  /**
   * Esquemas de validação para diferentes endpoints
   */
  getValidationSchemas() {
    return {
      // Validação para análise de IA
      aiAnalysis: {
        [Segments.BODY]: Joi.object({
          userInput: Joi.string()
            .min(10)
            .max(this.maxInputLength)
            .required()
            .messages({
              'string.min': 'Descrição muito curta. Mínimo 10 caracteres.',
              'string.max': `Descrição muito longa. Máximo ${this.maxInputLength} caracteres.`,
              'any.required': 'Descrição é obrigatória.'
            }),
          
          context: Joi.object({
            businessType: Joi.string().valid(
              'ecommerce', 'retail', 'services', 'technology', 
              'healthcare', 'education', 'finance', 'social_media',
              'manufacturing', 'consulting', 'other'
            ).optional(),
            
            userLevel: Joi.string().valid(
              'beginner', 'intermediate', 'advanced', 'executive'
            ).optional(),
            
            urgency: Joi.string().valid(
              'low', 'medium', 'high', 'critical'
            ).optional(),
            
            teamSize: Joi.number().integer().min(1).max(10000).optional(),
            
            additionalInfo: Joi.string().max(1000).optional()
          }).optional(),
          
          preferences: Joi.object({
            language: Joi.string().valid('pt-BR', 'en-US', 'es-ES').default('pt-BR'),
            outputFormat: Joi.string().valid('excel', 'csv', 'json').default('excel'),
            includeCharts: Joi.boolean().default(true),
            includeFormulas: Joi.boolean().default(true),
            complexityLevel: Joi.string().valid('basic', 'intermediate', 'advanced').default('intermediate')
          }).optional()
        })
      },

      // Validação para refinamento de planilha
      excelRefinement: {
        [Segments.BODY]: Joi.object({
          sessionId: Joi.string()
            .pattern(/^[a-f0-9]{32}$/)
            .required()
            .messages({
              'string.pattern.base': 'ID de sessão inválido.'
            }),
          
          modifications: Joi.array().items(
            Joi.object({
              type: Joi.string().valid(
                'add_column', 'remove_column', 'modify_formula',
                'change_chart', 'add_validation', 'format_cells',
                'add_sheet', 'remove_sheet', 'modify_data'
              ).required(),
              
              target: Joi.string().required(),
              value: Joi.any().required(),
              options: Joi.object().optional()
            })
          ).min(1).max(20).required(),
          
          reason: Joi.string().max(500).optional()
        })
      },

      // Validação para upload de arquivo
      fileUpload: {
        [Segments.BODY]: Joi.object({
          purpose: Joi.string().valid(
            'data_import', 'template_base', 'analysis_source'
          ).required(),
          
          description: Joi.string().max(500).optional()
        })
      },

      // Validação para feedback de usuário
      userFeedback: {
        [Segments.BODY]: Joi.object({
          sessionId: Joi.string().pattern(/^[a-f0-9]{32}$/).required(),
          
          rating: Joi.number().integer().min(1).max(5).required(),
          
          feedback: Joi.string().max(2000).optional(),
          
          categories: Joi.array().items(
            Joi.string().valid(
              'accuracy', 'performance', 'usability', 
              'features', 'design', 'support'
            )
          ).optional(),
          
          suggestion: Joi.string().max(1000).optional()
        })
      },

      // Validação para autenticação
      authentication: {
        [Segments.BODY]: Joi.object({
          email: Joi.string().email().required().messages({
            'string.email': 'Email inválido.'
          }),
          
          password: Joi.string().min(8).required().custom((value, helpers) => {
            if (!inputValidation.isStrongPassword(value)) {
              return helpers.error('password.weak');
            }
            return value;
          }).messages({
            'password.weak': 'Senha deve ter ao menos 8 caracteres, incluindo maiúscula, minúscula, número e símbolo.'
          }),
          
          rememberMe: Joi.boolean().optional()
        })
      }
    };
  }

  /**
   * Validação customizada de entrada de usuário
   */
  validateUserInput() {
    return (req, res, next) => {
      try {
        // Sanitizar strings de entrada
        if (req.body.userInput) {
          req.body.userInput = inputValidation.sanitizeString(req.body.userInput);
        }

        // Verificar caracteres suspeitos
        const suspiciousPatterns = [
          /<script/i,
          /javascript:/i,
          /onload=/i,
          /onerror=/i,
          /eval\(/i,
          /document\./i,
          /window\./i
        ];

        const inputText = JSON.stringify(req.body);
        for (const pattern of suspiciousPatterns) {
          if (pattern.test(inputText)) {
            logger.warn('Entrada suspeita detectada', {
              ip: req.ip,
              userAgent: req.get('User-Agent'),
              pattern: pattern.toString()
            });
            
            return res.status(400).json({
              success: false,
              error: 'Entrada contém caracteres não permitidos.',
              code: 'INVALID_INPUT'
            });
          }
        }

        next();
      } catch (error) {
        logger.error('Erro na validação de entrada:', error.message);
        return res.status(500).json({
          success: false,
          error: 'Erro interno na validação.',
          code: 'VALIDATION_ERROR'
        });
      }
    };
  }

  /**
   * Validação de arquivo upload
   */
  validateFileUpload() {
    return (req, res, next) => {
      try {
        if (!req.file && !req.files) {
          return next(); // Sem arquivo, continuar
        }

        const file = req.file || req.files[0];

        // Verificar tamanho do arquivo
        if (file.size > this.maxFileSize) {
          return res.status(400).json({
            success: false,
            error: `Arquivo muito grande. Máximo ${this.maxFileSize / 1024 / 1024}MB.`,
            code: 'FILE_TOO_LARGE'
          });
        }

        // Verificar tipo de arquivo
        if (!this.allowedFileTypes.includes(file.mimetype)) {
          return res.status(400).json({
            success: false,
            error: 'Tipo de arquivo não permitido.',
            code: 'INVALID_FILE_TYPE'
          });
        }

        // Verificar nome do arquivo
        const fileName = file.originalname;
        if (!/^[a-zA-Z0-9._-]+$/.test(fileName)) {
          return res.status(400).json({
            success: false,
            error: 'Nome do arquivo contém caracteres inválidos.',
            code: 'INVALID_FILENAME'
          });
        }

        logger.info('Arquivo validado com sucesso', {
          filename: fileName,
          size: file.size,
          mimetype: file.mimetype
        });

        next();
      } catch (error) {
        logger.error('Erro na validação de arquivo:', error.message);
        return res.status(500).json({
          success: false,
          error: 'Erro interno na validação de arquivo.',
          code: 'FILE_VALIDATION_ERROR'
        });
      }
    };
  }

  /**
   * Middleware de tratamento de erros de validação
   */
  handleValidationErrors() {
    return (err, req, res, next) => {
      if (err.isJoi || err.name === 'ValidationError') {
        const details = err.details || err.message;
        
        logger.warn('Erro de validação', {
          details,
          ip: req.ip,
          endpoint: req.path
        });

        return res.status(400).json({
          success: false,
          error: 'Dados de entrada inválidos.',
          details: details,
          code: 'VALIDATION_ERROR'
        });
      }

      next(err);
    };
  }

  /**
   * Validação de rate limiting personalizada
   */
  validateRateLimit(limitType = 'general') {
    return (req, res, next) => {
      // Esta validação será integrada com o sistema de rate limiting
      req.rateLimitType = limitType;
      next();
    };
  }

  /**
   * Validação de sessão ativa
   */
  validateSession() {
    return (req, res, next) => {
      try {
        const sessionId = req.headers['x-session-id'] || req.body.sessionId;
        
        if (sessionId && !inputValidation.isValidSessionId(sessionId)) {
          return res.status(400).json({
            success: false,
            error: 'ID de sessão inválido.',
            code: 'INVALID_SESSION_ID'
          });
        }

        req.sessionId = sessionId;
        next();
      } catch (error) {
        logger.error('Erro na validação de sessão:', error.message);
        return res.status(500).json({
          success: false,
          error: 'Erro interno na validação de sessão.',
          code: 'SESSION_VALIDATION_ERROR'
        });
      }
    };
  }
}

// Instância singleton
const validationMiddleware = new ValidationMiddleware();
const schemas = validationMiddleware.getValidationSchemas();

module.exports = {
  ValidationMiddleware,
  
  // Middlewares prontos para uso
  validateUserInput: validationMiddleware.validateUserInput(),
  validateFileUpload: validationMiddleware.validateFileUpload(),
  validateSession: validationMiddleware.validateSession(),
  handleValidationErrors: validationMiddleware.handleValidationErrors(),
  validateRateLimit: (type) => validationMiddleware.validateRateLimit(type),
  
  // Validações por endpoint usando celebrate
  validateAIAnalysis: celebrate(schemas.aiAnalysis),
  validateExcelRefinement: celebrate(schemas.excelRefinement),
  validateFileUploadBody: celebrate(schemas.fileUpload),
  validateUserFeedback: celebrate(schemas.userFeedback),
  validateAuthentication: celebrate(schemas.authentication),
  
  // Tratador de erros do celebrate
  celebrateErrors: errors()
}; 
