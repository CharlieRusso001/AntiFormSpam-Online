/**
 * Example configuration for AntiFormSpam
 * Copy this file and customize it for your needs
 */

const spamConfig = {
    // Entropy threshold (3.0-4.0 recommended)
    // Lower = more strict, Higher = more lenient
    entropyThreshold: 3.5,
    
    // Minimum string length to check entropy
    minLengthForEntropy: 8,
    
    // Suspicious email patterns (regex)
    suspiciousEmailPatterns: [
        /^\w+\.\w+\.\d+\.\d+@/,  // pattern like "oroq.e.ku1.45@gmail.com"
        /\d{4,}@/,  // 4+ consecutive digits before @
        /^[a-z]{1,3}\d+[a-z]{1,3}\d+@/,  // short letters + numbers pattern
        /^[a-z]\d+[a-z]\d+@/,  // single letter + number pattern
    ],
    
    // Common spam keywords to detect
    spamKeywords: [
        'viagra', 'casino', 'lottery', 'winner', 'click here',
        'free money', 'urgent', 'act now', 'limited time',
        'guaranteed', 'risk-free', 'no credit check'
    ],
    
    // Suspicious text patterns (regex)
    suspiciousPatterns: [
        /[A-Z]{5,}/,  // 5+ consecutive uppercase letters
        /[a-z]{10,}/,  // 10+ consecutive lowercase letters
        /\d{8,}/,  // 8+ consecutive digits
        /[A-Za-z]{15,}/,  // 15+ consecutive letters (likely random)
    ],
    
    // Enable phone number validation
    validatePhone: true,
    
    // Enable website URL validation
    validateWebsite: true,
    
    // Enable debug logging (set to false in production)
    debug: false,
    
    // Custom validation functions
    // Each function receives (fieldName, value, fieldType) and returns {valid: boolean, message?: string}
    customValidators: [
        // Example: Reject emails from specific domains
        function(fieldName, value, fieldType) {
            if (fieldType === 'email') {
                const blockedDomains = ['tempmail.com', '10minutemail.com'];
                const domain = value.split('@')[1];
                if (blockedDomains.includes(domain)) {
                    return {
                        valid: false,
                        message: 'Temporary email addresses are not allowed'
                    };
                }
            }
            return { valid: true };
        },
        
        // Example: Require minimum description length
        function(fieldName, value, fieldType) {
            if (fieldType === 'description' && value.length < 20) {
                return {
                    valid: false,
                    message: 'Description must be at least 20 characters'
                };
            }
            return { valid: true };
        }
    ]
};

// Usage:
// const spamDetector = new AntiFormSpam(spamConfig);

