/**
 * Validation Middleware - Request validation for API endpoints
 */

const { body } = require('express-validator');

// BSC address validation regex
const BSC_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

/**
 * Validate contract address in request body
 */
const validateContractAddress = [
  body('address')
    .matches(BSC_ADDRESS_REGEX)
    .withMessage('Invalid BSC contract address format'),
  body('quickScan')
    .optional()
    .isBoolean()
    .withMessage('quickScan must be a boolean'),
];

module.exports = {
  validateContractAddress,
  BSC_ADDRESS_REGEX
};
