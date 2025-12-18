const crypto = require('crypto');

/**
 * AES-256-GCM Encryption Handler
 */
class AESHandler {
    constructor() {
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32; // 256 bits
        this.ivLength = 12; // 96 bits for GCM
        this.saltLength = 16;
        this.tagLength = 16;
    }

    /**
     * Derive key from password using PBKDF2
     */
    deriveKey(password, salt) {
        return crypto.pbkdf2Sync(
            password,
            salt,
            100000, // iterations
            this.keyLength,
            'sha256'
        );
    }

    /**
     * Encrypt plaintext
     */
    encrypt(plaintext, password) {
        try {
            // Generate random salt and IV
            const salt = crypto.randomBytes(this.saltLength);
            const iv = crypto.randomBytes(this.ivLength);
            
            // Derive key from password
            const key = this.deriveKey(password, salt);
            
            // Create cipher
            const cipher = crypto.createCipheriv(this.algorithm, key, iv);
            
            // Encrypt
            let encrypted = cipher.update(plaintext, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            
            // Get authentication tag
            const authTag = cipher.getAuthTag();
            
            // Combine salt + iv + authTag + encrypted data
            const result = Buffer.concat([
                salt,
                iv,
                authTag,
                Buffer.from(encrypted, 'hex')
            ]);
            
            return {
                success: true,
                data: result.toString('base64')
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Decrypt ciphertext
     */
    decrypt(ciphertext, password) {
        try {
            // Decode from base64
            const buffer = Buffer.from(ciphertext, 'base64');
            
            // Extract components
            const salt = buffer.subarray(0, this.saltLength);
            const iv = buffer.subarray(this.saltLength, this.saltLength + this.ivLength);
            const authTag = buffer.subarray(
                this.saltLength + this.ivLength,
                this.saltLength + this.ivLength + this.tagLength
            );
            const encrypted = buffer.subarray(this.saltLength + this.ivLength + this.tagLength);
            
            // Derive key from password
            const key = this.deriveKey(password, salt);
            
            // Create decipher
            const decipher = crypto.createDecipheriv(this.algorithm, key, iv);
            decipher.setAuthTag(authTag);
            
            // Decrypt
            let decrypted = decipher.update(encrypted, null, 'utf8');
            decrypted += decipher.final('utf8');
            
            return {
                success: true,
                data: decrypted
            };
        } catch (error) {
            return {
                success: false,
                error: 'Decryption failed. Invalid password or corrupted data.'
            };
        }
    }
}

/**
 * ChaCha20-Poly1305 Encryption Handler
 */
class ChaChaHandler {
    constructor() {
        this.algorithm = 'chacha20-poly1305';
        this.keyLength = 32; // 256 bits
        this.ivLength = 12; // 96 bits
        this.saltLength = 16;
        this.tagLength = 16;
    }

    deriveKey(password, salt) {
        return crypto.pbkdf2Sync(password, salt, 100000, this.keyLength, 'sha256');
    }

    encrypt(plaintext, password) {
        try {
            const salt = crypto.randomBytes(this.saltLength);
            const iv = crypto.randomBytes(this.ivLength);
            const key = this.deriveKey(password, salt);
            
            const cipher = crypto.createCipheriv(this.algorithm, key, iv, {
                authTagLength: this.tagLength
            });
            
            let encrypted = cipher.update(plaintext, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const authTag = cipher.getAuthTag();
            
            const result = Buffer.concat([
                salt,
                iv,
                authTag,
                Buffer.from(encrypted, 'hex')
            ]);
            
            return {
                success: true,
                data: result.toString('base64')
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    decrypt(ciphertext, password) {
        try {
            const buffer = Buffer.from(ciphertext, 'base64');
            
            const salt = buffer.subarray(0, this.saltLength);
            const iv = buffer.subarray(this.saltLength, this.saltLength + this.ivLength);
            const authTag = buffer.subarray(
                this.saltLength + this.ivLength,
                this.saltLength + this.ivLength + this.tagLength
            );
            const encrypted = buffer.subarray(this.saltLength + this.ivLength + this.tagLength);
            
            const key = this.deriveKey(password, salt);
            
            const decipher = crypto.createDecipheriv(this.algorithm, key, iv, {
                authTagLength: this.tagLength
            });
            decipher.setAuthTag(authTag);
            
            let decrypted = decipher.update(encrypted, null, 'utf8');
            decrypted += decipher.final('utf8');
            
            return {
                success: true,
                data: decrypted
            };
        } catch (error) {
            return {
                success: false,
                error: 'Decryption failed. Invalid password or corrupted data.'
            };
        }
    }
}

/**
 * RSA Encryption Handler
 */
class RSAHandler {
    constructor() {
        this.keySize = 2048;
        this.padding = crypto.constants.RSA_PKCS1_OAEP_PADDING;
    }

    /**
     * Generate RSA key pair
     */
    generateKeyPair() {
        try {
            const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: this.keySize,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });
            
            return {
                success: true,
                publicKey,
                privateKey
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Encrypt with public key
     */
    encrypt(plaintext, publicKey) {
        try {
            const buffer = Buffer.from(plaintext, 'utf8');
            const encrypted = crypto.publicEncrypt(
                {
                    key: publicKey,
                    padding: this.padding
                },
                buffer
            );
            
            return {
                success: true,
                data: encrypted.toString('base64')
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Decrypt with private key
     */
    decrypt(ciphertext, privateKey) {
        try {
            const buffer = Buffer.from(ciphertext, 'base64');
            const decrypted = crypto.privateDecrypt(
                {
                    key: privateKey,
                    padding: this.padding
                },
                buffer
            );
            
            return {
                success: true,
                data: decrypted.toString('utf8')
            };
        } catch (error) {
            return {
                success: false,
                error: 'Decryption failed. Invalid key or corrupted data.'
            };
        }
    }
}

module.exports = {
    AESHandler,
    ChaChaHandler,
    RSAHandler
};
