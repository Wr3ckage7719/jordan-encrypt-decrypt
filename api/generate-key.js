const { RSAHandler } = require('../lib/cryptoHandlers');
const { SubstitutionCipher } = require('../lib/classicalCiphers');

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

    // Only accept GET and POST requests
    if (req.method !== 'GET' && req.method !== 'POST') {
        return res.status(405).json({ success: false, error: 'Method not allowed' });
    }

    try {
        const keyType = req.method === 'GET' ? req.query.type : req.body.type;

        if (!keyType) {
            return res.status(400).json({
                success: false,
                error: 'Key type is required (rsa or substitution)'
            });
        }

        let result;

        switch (keyType.toLowerCase()) {
            case 'rsa':
                const rsa = new RSAHandler();
                result = rsa.generateKeyPair();
                break;

            case 'substitution':
                const substitution = new SubstitutionCipher();
                const key = substitution.generateKey();
                result = {
                    success: true,
                    key: key
                };
                break;

            default:
                return res.status(400).json({
                    success: false,
                    error: `Unknown key type: ${keyType}`
                });
        }

        return res.status(200).json(result);

    } catch (error) {
        console.error('Key generation error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error during key generation'
        });
    }
};
