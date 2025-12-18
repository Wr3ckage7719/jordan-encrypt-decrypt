// Utility Functions

/**
 * Show status message
 */
function showStatus(message, type = 'info') {
    const statusEl = document.getElementById('statusMessage');
    statusEl.textContent = message;
    statusEl.className = `status-message ${type}`;
    statusEl.classList.add('show');
    
    setTimeout(() => {
        statusEl.classList.remove('show');
    }, 4000);
}

/**
 * Show loading overlay
 */
function showLoading(show = true) {
    const overlay = document.getElementById('loadingOverlay');
    if (show) {
        overlay.classList.add('show');
    } else {
        overlay.classList.remove('show');
    }
}

/**
 * Calculate password strength
 */
function calculatePasswordStrength(password) {
    if (!password) return { strength: 0, text: '', color: '#94a3b8' };
    
    let strength = 0;
    const checks = {
        length: password.length >= 8,
        lowercase: /[a-z]/.test(password),
        uppercase: /[A-Z]/.test(password),
        numbers: /[0-9]/.test(password),
        special: /[^a-zA-Z0-9]/.test(password)
    };
    
    strength += checks.length ? 20 : 0;
    strength += checks.lowercase ? 20 : 0;
    strength += checks.uppercase ? 20 : 0;
    strength += checks.numbers ? 20 : 0;
    strength += checks.special ? 20 : 0;
    
    let text = '';
    let color = '';
    
    if (strength <= 40) {
        text = 'Weak';
        color = '#ef4444';
    } else if (strength <= 60) {
        text = 'Fair';
        color = '#f59e0b';
    } else if (strength <= 80) {
        text = 'Good';
        color = '#3b82f6';
    } else {
        text = 'Strong';
        color = '#10b981';
    }
    
    return { strength, text, color };
}

/**
 * Validate input based on method
 */
function validateInput(method, data) {
    if (!data.plaintext && !data.ciphertext) {
        return { valid: false, error: 'Please enter text or upload a file' };
    }
    
    switch (method) {
        case 'aes':
        case 'chacha20':
            if (!data.password) {
                return { valid: false, error: 'Password is required' };
            }
            if (data.password.length < 6) {
                return { valid: false, error: 'Password must be at least 6 characters' };
            }
            break;
            
        case 'rsa':
            if (!data.key) {
                return { valid: false, error: 'RSA key is required' };
            }
            break;
            
        case 'substitution':
            if (!data.key) {
                return { valid: false, error: 'Substitution key is required' };
            }
            if (data.key.length !== 26) {
                return { valid: false, error: 'Substitution key must be exactly 26 letters' };
            }
            break;
            
        case 'caesar':
            const shift = parseInt(data.shift);
            if (isNaN(shift) || shift < 1 || shift > 25) {
                return { valid: false, error: 'Shift must be between 1 and 25' };
            }
            break;
    }
    
    return { valid: true };
}

/**
 * Get method information
 */
function getMethodInfo(method) {
    const info = {
        'aes': 'AES-256-GCM is a secure, modern encryption algorithm suitable for protecting sensitive data. Uses password-based key derivation.',
        'chacha20': 'ChaCha20-Poly1305 is a modern stream cipher with authenticated encryption. Alternative to AES with excellent performance.',
        'rsa': 'RSA-2048 uses asymmetric encryption with public/private key pairs. Suitable for small data and key exchange.',
        'caesar': '⚠️ Caesar cipher is a simple substitution cipher for educational purposes only. NOT secure for real data!',
        'substitution': '⚠️ Substitution cipher replaces each letter with another. Educational only - NOT secure for real data!',
        'base64': '⚠️ Base64 is encoding, NOT encryption. Provides NO security - anyone can decode it!'
    };
    
    return info[method] || 'Select an encryption method to see details.';
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        // Fallback for older browsers
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
    }
}

/**
 * API call helper
 */
async function apiCall(endpoint, data) {
    const apiBase = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:3000'
        : '';
    
    try {
        const response = await fetch(`${apiBase}/api/${endpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });
        
        const j = await response.json();
        // Normalize response shapes from different handlers
        if (typeof j === 'string') return { success: true, data: j };
        if (j === null || j === undefined) return { success: false, error: 'Empty response' };
        if (typeof j === 'object') {
            if (j.success !== undefined) return j;
            // common aliases
            const data = j.data || j.result || j.plaintext || j.ciphertext || j.text;
            if (data !== undefined) return { success: true, data };
            // fallback - return object as data
            return { success: true, data: j };
        }
        return { success: false, error: 'Unexpected response format' };
    } catch (error) {
        return {
            success: false,
            error: 'Network error: ' + error.message
        };
    }
}

/**
 * Generate API call for key generation
 */
async function generateKeyAPI(type) {
    const apiBase = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'http://localhost:3000'
        : '';
    
    try {
        const response = await fetch(`${apiBase}/api/generate-key?type=${type}`, {
            method: 'GET'
        });
        
        const result = await response.json();
        return result;
    } catch (error) {
        return {
            success: false,
            error: 'Network error: ' + error.message
        };
    }
}
