const { AESHandler, ChaChaHandler, RSAHandler } = require('../lib/cryptoHandlers');
const { CaesarCipher, SubstitutionCipher, Base64Handler, ReverseCipher, HexHandler, MorseCode, BinaryHandler, AtbashCipher, ROT13Cipher } = require('../lib/classicalCiphers');

module.exports = async (req, res) => {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    // Handle OPTIONS request
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    // Only accept POST requests
    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: 'Method not allowed' });
    }

    try {
        const { method, ciphertext, password, key, shift } = req.body;

        // Validate input
        if (!method || !ciphertext) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields: method and ciphertext'
            });
        }

        let result;

        switch (method.toLowerCase()) {
            case 'aes':
            case 'aes-256-gcm':
                if (!password) {
                    return res.status(400).json({
                        success: false,
                        error: 'Password is required for AES decryption'
                    });
                }
                const aes = new AESHandler();
                result = aes.decrypt(ciphertext, password);
                break;

            case 'chacha20':
            case 'chacha20-poly1305':
                if (!password) {
                    return res.status(400).json({
                        success: false,
                        error: 'Password is required for ChaCha20 decryption'
                    });
                }
                const chacha = new ChaChaHandler();
                result = chacha.decrypt(ciphertext, password);
                break;

            case 'rsa':
                if (!key) {
                    return res.status(400).json({
                        success: false,
                        error: 'Private key is required for RSA decryption'
                    });
                }
                const rsa = new RSAHandler();
                result = rsa.decrypt(ciphertext, key);
                break;

            case 'caesar':
                const caesar = new CaesarCipher();
                const caesarShift = shift || 3;
                const decrypted = caesar.decrypt(ciphertext, caesarShift);
                result = {
                    success: true,
                    data: decrypted
                };
                break;

            case 'substitution':
                if (!key) {
                    return res.status(400).json({
                        success: false,
                        error: 'Substitution key is required'
                    });
                }
                const substitution = new SubstitutionCipher();
                result = substitution.decrypt(ciphertext, key);
                break;

            case 'base64':
                const base64 = new Base64Handler();
                result = base64.decode(ciphertext);
                break;

            case 'reverse':
                const reverse = new ReverseCipher();
                result = reverse.reverse(ciphertext);
                break;

            case 'hex':
                const hex = new HexHandler();
                result = hex.decode(ciphertext);
                break;

            case 'morse':
                const morse = new MorseCode();
                result = morse.decode(ciphertext);
                break;

            case 'binary':
                const binary = new BinaryHandler();
                result = binary.decode(ciphertext);
                break;

            case 'atbash':
                const atbash = new AtbashCipher();
                result = atbash.cipher(ciphertext);
                break;

            case 'rot13':
                const rot13 = new ROT13Cipher();
                result = rot13.cipher(ciphertext);
                break;

            default:
                return res.status(400).json({
                    success: false,
                    error: `Unknown decryption method: ${method}`
                });
        }

        return res.status(200).json(result);

    } catch (error) {
        console.error('Decryption error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error during decryption'
        });
    }
};
