// Encryption Manager (Static)
// Handles password encryption, verification, and token generation

// Imports
import argon2 from 'argon2';
import crypto from 'crypto';

// enum-like structure to indicate password policy validation results
export const PasswordPolicyValidationCode = {
    VALID: "OK",
    TOO_SHORT: "Password is too short.",
    MISSING_UPPERCASE: "Password must contain at least one uppercase letter.",
    MISSING_LOWERCASE: "Password must contain at least one lowercase letter.",
    MISSING_DIGIT: "Password must contain at least one digit.",
    MISSING_SPECIAL_CHAR: "Password must contain at least one special character."
}

// Config for Argon2 hashing
const ARGON2_CONFIG = {
    type: argon2.argon2id,  // Uses a hybrid approach (best for most cases)
    memoryCost: 65536,      // 64 MB memory cost
    timeCost: 3,            // Number of iterations
    parallelism: 4          // Number of parallel threads
}

// Password policy settings
const PASSWORD_SETTINGS = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireDigit: true,
    requireSpecialChar: true
}

class EncryptionManager {
    // Validates a password against the defined policy (see above)
    static async validatePasswordPolicy(password) {
        if (password.length < PASSWORD_SETTINGS.minLength) {
            return PasswordPolicyValidationCode.TOO_SHORT;
        }
        if (PASSWORD_SETTINGS.requireUppercase && !/[A-Z]/.test(password)) {
            return PasswordPolicyValidationCode.MISSING_UPPERCASE;
        }
        if (PASSWORD_SETTINGS.requireLowercase && !/[a-z]/.test(password)) {
            return PasswordPolicyValidationCode.MISSING_LOWERCASE;
        }
        if (PASSWORD_SETTINGS.requireDigit && !/[0-9]/.test(password)) {
            return PasswordPolicyValidationCode.MISSING_DIGIT;
        }
        if (PASSWORD_SETTINGS.requireSpecialChar && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            return PasswordPolicyValidationCode.MISSING_SPECIAL_CHAR;
        }
        return PasswordPolicyValidationCode.VALID;
    }

    // Encrypts a plaintext password using Argon2
    static async encryptPassword(plaintextPassword) {
        return await argon2.hash(plaintextPassword, ARGON2_CONFIG);
    }

    // Verifies a plaintext password against a hashed password
    static async verifyPassword(hashedPassword, plaintextPassword) {
        try {
            return await argon2.verify(hashedPassword, plaintextPassword, ARGON2_CONFIG);
        } catch (err) {
            return false;
        }
    }

    // Generates a secure random token
    static generateRandomToken(length = 32) {
        return crypto.randomBytes(length).toString('hex');
    }
}

export default EncryptionManager;