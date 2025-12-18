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
        const { method, plaintext, password, key, shift } = req.body;

        // Validate input
        if (!method || !plaintext) {
            return res.status(400).json({
                success: false,
                error: 'Missing required fields: method and plaintext'
            });
        }

        let result;

        switch (method.toLowerCase()) {
            case 'aes':
            case 'aes-256-gcm':
                if (!password) {
                    return res.status(400).json({
                        success: false,
                        error: 'Password is required for AES encryption'
                    });
                }
                const aes = new AESHandler();
                result = aes.encrypt(plaintext, password);
                break;

            case 'chacha20':
            case 'chacha20-poly1305':
                if (!password) {
                    return res.status(400).json({
                        success: false,
                        error: 'Password is required for ChaCha20 encryption'
                    });
                }
                const chacha = new ChaChaHandler();
                result = chacha.encrypt(plaintext, password);
                break;

            case 'rsa':
                if (!key) {
                    return res.status(400).json({
                        success: false,
                        error: 'Public key is required for RSA encryption'
                    });
                }
                const rsa = new RSAHandler();
                result = rsa.encrypt(plaintext, key);
                break;

            case 'caesar':
                const caesar = new CaesarCipher();
                const caesarShift = shift || 3;
                const encrypted = caesar.encrypt(plaintext, caesarShift);
                result = {
                    success: true,
                    data: encrypted,
                    shift: caesarShift
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
                result = substitution.encrypt(plaintext, key);
                break;

            case 'base64':
                const base64 = new Base64Handler();
                result = base64.encode(plaintext);
                break;

            case 'reverse':
                const reverse = new ReverseCipher();
                result = reverse.reverse(plaintext);
                break;

            case 'hex':
                const hex = new HexHandler();
                result = hex.encode(plaintext);
                break;

            case 'morse':
                const morse = new MorseCode();
                result = morse.encode(plaintext);
                break;

            case 'binary':
                const binary = new BinaryHandler();
                result = binary.encode(plaintext);
                break;

            case 'atbash':
                const atbash = new AtbashCipher();
                result = atbash.cipher(plaintext);
                break;

            case 'rot13':
                const rot13 = new ROT13Cipher();
                result = rot13.cipher(plaintext);
                break;

            default:
                return res.status(400).json({
                    success: false,
                    error: `Unknown encryption method: ${method}`
                });
        }

        return res.status(200).json(result);

    } catch (error) {
        console.error('Encryption error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error during encryption'
        });
    }
};
