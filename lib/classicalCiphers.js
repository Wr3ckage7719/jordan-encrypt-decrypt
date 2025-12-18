/**
 * Classical Cipher Implementations (Educational purposes only)
 */

/**
 * Caesar Cipher
 */
class CaesarCipher {
    constructor() {
        this.defaultShift = 3;
    }

    /**
     * Encrypt using Caesar cipher
     */
    encrypt(plaintext, shift = this.defaultShift) {
        shift = parseInt(shift) || this.defaultShift;
        shift = ((shift % 26) + 26) % 26; // Normalize shift
        
        return plaintext.split('').map(char => {
            if (char.match(/[a-z]/i)) {
                const code = char.charCodeAt(0);
                const isUpperCase = char === char.toUpperCase();
                const base = isUpperCase ? 65 : 97;
                
                return String.fromCharCode(((code - base + shift) % 26) + base);
            }
            return char;
        }).join('');
    }

    /**
     * Decrypt using Caesar cipher
     */
    decrypt(ciphertext, shift = this.defaultShift) {
        shift = parseInt(shift) || this.defaultShift;
        return this.encrypt(ciphertext, 26 - shift);
    }
}

/**
 * Substitution Cipher
 */
class SubstitutionCipher {
    constructor() {
        this.alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    }

    /**
     * Generate a random substitution key
     */
    generateKey() {
        const shuffled = this.alphabet.split('').sort(() => Math.random() - 0.5);
        return shuffled.join('');
    }

    /**
     * Validate substitution key
     */
    validateKey(key) {
        if (!key || key.length !== 26) return false;
        const sorted = key.toUpperCase().split('').sort().join('');
        return sorted === this.alphabet;
    }

    /**
     * Encrypt using substitution cipher
     */
    encrypt(plaintext, key) {
        if (!this.validateKey(key)) {
            return {
                success: false,
                error: 'Invalid substitution key. Must be 26 unique letters.'
            };
        }

        key = key.toUpperCase();
        const result = plaintext.split('').map(char => {
            if (char.match(/[a-z]/i)) {
                const isUpperCase = char === char.toUpperCase();
                const upperChar = char.toUpperCase();
                const index = this.alphabet.indexOf(upperChar);
                
                if (index !== -1) {
                    const substituted = key[index];
                    return isUpperCase ? substituted : substituted.toLowerCase();
                }
            }
            return char;
        }).join('');

        return {
            success: true,
            data: result
        };
    }

    /**
     * Decrypt using substitution cipher
     */
    decrypt(ciphertext, key) {
        if (!this.validateKey(key)) {
            return {
                success: false,
                error: 'Invalid substitution key. Must be 26 unique letters.'
            };
        }

        key = key.toUpperCase();
        const result = ciphertext.split('').map(char => {
            if (char.match(/[a-z]/i)) {
                const isUpperCase = char === char.toUpperCase();
                const upperChar = char.toUpperCase();
                const index = key.indexOf(upperChar);
                
                if (index !== -1) {
                    const original = this.alphabet[index];
                    return isUpperCase ? original : original.toLowerCase();
                }
            }
            return char;
        }).join('');

        return {
            success: true,
            data: result
        };
    }
}

/**
 * Base64 Encoding (not encryption!)
 */
class Base64Handler {
    /**
     * Encode to Base64
     */
    encode(plaintext) {
        try {
            const buffer = Buffer.from(plaintext, 'utf8');
            return {
                success: true,
                data: buffer.toString('base64')
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Decode from Base64
     */
    decode(encoded) {
        try {
            const buffer = Buffer.from(encoded, 'base64');
            return {
                success: true,
                data: buffer.toString('utf8')
            };
        } catch (error) {
            return {
                success: false,
                error: 'Invalid Base64 string'
            };
        }
    }
}

/**
 * Reverse Text (simple cipher)
 */
class ReverseCipher {
    reverse(text) {
        try {
            return {
                success: true,
                data: text.split('').reverse().join('')
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

/**
 * Hexadecimal Encoding
 */
class HexHandler {
    encode(text) {
        try {
            const buffer = Buffer.from(text, 'utf8');
            return {
                success: true,
                data: buffer.toString('hex')
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    decode(hex) {
        try {
            const buffer = Buffer.from(hex, 'hex');
            return {
                success: true,
                data: buffer.toString('utf8')
            };
        } catch (error) {
            return {
                success: false,
                error: 'Invalid hexadecimal string'
            };
        }
    }
}

/**
 * Morse Code
 */
class MorseCode {
    constructor() {
        this.morseMap = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/', '.': '.-.-.-', ',': '--..--',
            '?': '..--..', '!': '-.-.--', ':': '---...', ';': '-.-.-.', '-': '-....-'
        };
        
        this.reverseMap = {};
        for (let key in this.morseMap) {
            this.reverseMap[this.morseMap[key]] = key;
        }
    }

    encode(text) {
        try {
            const morse = text.toUpperCase().split('').map(char => 
                this.morseMap[char] || char
            ).join(' ');
            
            return {
                success: true,
                data: morse
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    decode(morse) {
        try {
            const text = morse.split(' ').map(code => 
                this.reverseMap[code] || code
            ).join('');
            
            return {
                success: true,
                data: text
            };
        } catch (error) {
            return {
                success: false,
                error: 'Invalid morse code'
            };
        }
    }
}

/**
 * Binary Encoding
 */
class BinaryHandler {
    encode(text) {
        try {
            const binary = text.split('').map(char => {
                const bin = char.charCodeAt(0).toString(2);
                return bin.padStart(8, '0');
            }).join(' ');
            
            return {
                success: true,
                data: binary
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    decode(binary) {
        try {
            const text = binary.split(' ').map(bin => 
                String.fromCharCode(parseInt(bin, 2))
            ).join('');
            
            return {
                success: true,
                data: text
            };
        } catch (error) {
            return {
                success: false,
                error: 'Invalid binary string'
            };
        }
    }
}

/**
 * Atbash Cipher (reverses alphabet)
 */
class AtbashCipher {
    cipher(text) {
        try {
            const result = text.split('').map(char => {
                if (char.match(/[a-z]/i)) {
                    const code = char.charCodeAt(0);
                    const isUpperCase = char === char.toUpperCase();
                    const base = isUpperCase ? 65 : 97;
                    return String.fromCharCode(base + (25 - (code - base)));
                }
                return char;
            }).join('');
            
            return {
                success: true,
                data: result
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

/**
 * ROT13 Cipher (Caesar with shift 13)
 */
class ROT13Cipher {
    cipher(text) {
        try {
            const result = text.split('').map(char => {
                if (char.match(/[a-z]/i)) {
                    const code = char.charCodeAt(0);
                    const isUpperCase = char === char.toUpperCase();
                    const base = isUpperCase ? 65 : 97;
                    return String.fromCharCode(((code - base + 13) % 26) + base);
                }
                return char;
            }).join('');
            
            return {
                success: true,
                data: result
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }
}

module.exports = {
    CaesarCipher,
    SubstitutionCipher,
    Base64Handler,
    ReverseCipher,
    HexHandler,
    MorseCode,
    BinaryHandler,
    AtbashCipher,
    ROT13Cipher
};
