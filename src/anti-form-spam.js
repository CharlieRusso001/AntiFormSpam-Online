/**
 * AntiFormSpam - A comprehensive spam detection system for web forms
 * Detects spam patterns including random strings, suspicious emails, and bot submissions
 */

class AntiFormSpam {
    constructor(options = {}) {
        this.config = {
            // Entropy threshold for detecting random strings (higher = more strict)
            entropyThreshold: options.entropyThreshold || 3.5,
            
            // Minimum length to check entropy
            minLengthForEntropy: options.minLengthForEntropy || 8,
            
            // Suspicious email patterns
            suspiciousEmailPatterns: options.suspiciousEmailPatterns || [
                /^\w+\.\w+\.\d+\.\d+@/,  // pattern like "oroq.e.ku1.45@gmail.com"
                /\d{4,}@/,  // 4+ consecutive digits before @
                /^[a-z]{1,3}\d+[a-z]{1,3}\d+@/,  // short letters + numbers pattern
            ],
            
            // Common spam keywords
            spamKeywords: options.spamKeywords || [
                'viagra', 'casino', 'lottery', 'winner', 'click here',
                'free money', 'urgent', 'act now', 'limited time'
            ],
            
            // Suspicious patterns in text
            suspiciousPatterns: options.suspiciousPatterns || [
                /[A-Z]{5,}/,  // 5+ consecutive uppercase letters
                /[a-z]{10,}/,  // 10+ consecutive lowercase letters
                /\d{8,}/,  // 8+ consecutive digits
                /[A-Za-z]{15,}/,  // 15+ consecutive letters (likely random)
            ],
            
            // Phone number validation
            validatePhone: options.validatePhone !== false,
            
            // Email validation (client-side only, no external APIs)
            useEmailValidatorApi: options.useEmailValidatorApi || false,
            
            // Website URL validation
            validateWebsite: options.validateWebsite !== false,
            
            // Enable logging
            debug: options.debug || false,
            
            // Custom validation functions
            customValidators: options.customValidators || [],
        };
    }

    /**
     * Calculate Shannon entropy of a string
     * Higher entropy = more random/less predictable
     */
    calculateEntropy(str) {
        if (!str || str.length === 0) return 0;
        
        const freq = {};
        for (let char of str) {
            freq[char] = (freq[char] || 0) + 1;
        }
        
        let entropy = 0;
        const length = str.length;
        
        for (let char in freq) {
            const p = freq[char] / length;
            entropy -= p * Math.log2(p);
        }
        
        return entropy;
    }

    /**
     * Check if text contains actual words (vs random characters)
     */
    containsActualWords(text) {
        if (!text) return false;
        
        // Remove punctuation and split into words
        const words = text.toLowerCase()
            .replace(/[^\w\s]/g, ' ')
            .split(/\s+/)
            .filter(w => w.length > 0);
        
        if (words.length === 0) return false;
        
        // Common English words that indicate legitimate text
        const commonWords = [
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
            'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
            'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
            'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their',
            'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go',
            'me', 'when', 'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know',
            'take', 'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them',
            'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its', 'over',
            'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
            'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these', 'give', 'day',
            'most', 'us', 'hello', 'hi', 'interested', 'discuss', 'project', 'team', 'services',
            'would', 'like', 'learn', 'more', 'about', 'contact', 'information', 'please', 'thank'
        ];
        
        // Check if at least 30% of words are common words (for longer text)
        // Or if text is short, at least one common word
        const commonWordCount = words.filter(w => commonWords.includes(w)).length;
        const wordRatio = commonWordCount / words.length;
        
        // For longer text (20+ words), require lower ratio
        // For shorter text, require at least one common word
        if (words.length >= 20) {
            return wordRatio >= 0.15; // At least 15% common words
        } else {
            return commonWordCount >= 1; // At least one common word
        }
    }

    /**
     * Check if a string appears to be random/high entropy
     */
    isRandomString(str, isDescription = false) {
        if (!str || str.length < this.config.minLengthForEntropy) {
            return false;
        }
        
        // For descriptions, check if it contains actual words first
        if (isDescription && this.containsActualWords(str)) {
            // If it has actual words, be more lenient with entropy
            const entropy = this.calculateEntropy(str);
            // Use higher threshold for descriptions with actual words
            const threshold = this.config.entropyThreshold + 0.5;
            const isRandom = entropy > threshold;
            
            if (this.config.debug) {
                console.log(`Description entropy check (with words): ${entropy.toFixed(2)} (threshold: ${threshold})`);
            }
            
            return isRandom;
        }
        
        const entropy = this.calculateEntropy(str);
        const isRandom = entropy > this.config.entropyThreshold;
        
        if (this.config.debug) {
            console.log(`Entropy check for "${str}": ${entropy.toFixed(2)} (threshold: ${this.config.entropyThreshold})`);
        }
        
        return isRandom;
    }

    /**
     * Check if email appears suspicious
     */
    isSuspiciousEmail(email) {
        if (!email) return false;
        
        const lowerEmail = email.toLowerCase();
        
        // Check against suspicious patterns
        for (let pattern of this.config.suspiciousEmailPatterns) {
            if (pattern.test(email)) {
                if (this.config.debug) {
                    console.log(`Suspicious email pattern matched: ${email}`);
                }
                return true;
            }
        }
        
        // Check for high entropy in local part (before @)
        const localPart = email.split('@')[0];
        if (localPart && this.isRandomString(localPart)) {
            if (this.config.debug) {
                console.log(`High entropy in email local part: ${email}`);
            }
            return true;
        }
        
        return false;
    }

    /**
     * Enhanced email validation (client-side only, no external APIs)
     */
    async validateEmailWithAPI(email) {
        if (!email || !this.config.useEmailValidatorApi) {
            return {
                valid: !this.isSuspiciousEmail(email) && this.isValidEmailFormat(email),
                details: { method: 'basic_format_check' }
            };
        }

        // Simulate async for consistency
        await new Promise(resolve => setTimeout(resolve, 50));

        // Basic format validation first
        if (!this.isValidEmailFormat(email)) {
            return {
                valid: false,
                details: { method: 'format_check', reason: 'Invalid email format' }
            };
        }

        // Suspicious pattern check
        if (this.isSuspiciousEmail(email)) {
            return {
                valid: false,
                details: { method: 'pattern_check', reason: 'Suspicious email pattern detected' }
            };
        }

        // Extract domain
        const parts = email.split('@');
        if (parts.length !== 2) {
            return {
                valid: false,
                details: { method: 'format_check', reason: 'Invalid email format' }
            };
        }

        const domain = parts[1].toLowerCase();
        
        // Check for disposable/temporary email domains (comprehensive list)
        const disposableDomains = [
            'tempmail.com', '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
            'throwaway.email', 'temp-mail.org', 'getnada.com', 'mohmal.com',
            'yopmail.com', 'sharklasers.com', 'grr.la', 'guerrillamailblock.com',
            'pokemail.net', 'spam4.me', 'bccto.me', 'chitthi.in', 'dispostable.com',
            'mintemail.com', 'mytrashmail.com', 'tempail.com', 'trashmail.com',
            'emailondeck.com', 'fakeinbox.com', 'getairmail.com', 'inboxkitten.com',
            'maildrop.cc', 'meltmail.com', 'mintemail.com', 'mohmal.com', 'mytemp.email',
            'nada.email', 'sharklasers.com', 'temp-mail.io', 'tempmailo.com', 'tmpmail.org',
            'trashmail.net', 'throwawaymail.com', 'tempr.email', 'mailcatch.com', 'maildrop.cc',
            'getnada.com', 'mailinator.com', 'guerrillamail.info', 'mailnesia.com', 'melt.li',
            'mintemail.com', 'mohmal.com', 'mytemp.email', 'nada.email', 'sharklasers.com',
            'temp-mail.io', 'tempmailo.com', 'tmpmail.org', 'trashmail.net', 'throwawaymail.com'
        ];
        
        const isDisposable = disposableDomains.some(d => domain.includes(d) || domain === d);
        
        if (isDisposable) {
            return {
                valid: false,
                details: {
                    method: 'client_validation',
                    reason: 'Temporary/disposable email address',
                    disposable: true,
                    domain: domain
                }
            };
        }

        // Check for free email providers
        const freeProviders = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'icloud.com', 'mail.com', 'protonmail.com', 'zoho.com', 'yandex.com',
            'gmx.com', 'live.com', 'msn.com', 'inbox.com', 'mail.ru', 'qq.com',
            '163.com', 'sina.com', 'rediffmail.com', 'mail.com', 'fastmail.com'
        ];
        
        const isFreeProvider = freeProviders.some(provider => domain === provider);

        return {
            valid: true,
            details: {
                method: 'client_validation',
                disposable: false,
                domain: domain,
                free_provider: isFreeProvider
            }
        };
    }

    /**
     * Basic email format validation
     */
    isValidEmailFormat(email) {
        if (!email) return false;
        
        // Basic email regex pattern
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return false;
        }
        
        // Check for valid length
        if (email.length < 5 || email.length > 254) {
            return false;
        }
        
        // Check local part (before @)
        const localPart = email.split('@')[0];
        if (localPart.length === 0 || localPart.length > 64) {
            return false;
        }
        
        // Check domain part (after @)
        const domainPart = email.split('@')[1];
        if (!domainPart || domainPart.length < 4 || !domainPart.includes('.')) {
            return false;
        }
        
        return true;
    }

    /**
     * Check if text contains spam keywords
     */
    containsSpamKeywords(text) {
        if (!text) return false;
        
        const lowerText = text.toLowerCase();
        for (let keyword of this.config.spamKeywords) {
            if (lowerText.includes(keyword)) {
                if (this.config.debug) {
                    console.log(`Spam keyword found: ${keyword}`);
                }
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if text matches suspicious patterns
     */
    matchesSuspiciousPatterns(text, isDescription = false) {
        if (!text) return false;
        
        // For descriptions, be smarter about pattern matching
        if (isDescription) {
            // If text contains actual words, be very lenient with pattern matching
            if (this.containsActualWords(text)) {
                // Only flag very obvious spam patterns
                // Multiple consecutive uppercase letters in the middle of text (not at start)
                if (/[a-z\s][A-Z]{6,}/.test(text)) {
                    return true;
                }
                
                // Very long sequences without spaces (30+ chars)
                if (/[A-Za-z0-9]{30,}/.test(text) && !/\s/.test(text)) {
                    return true;
                }
                
                // Skip other pattern checks if text has actual words
                return false;
            }
            
            // For text without actual words, check all patterns
            // But still check if pattern is part of a word boundary
            for (let pattern of this.config.suspiciousPatterns) {
                const regex = new RegExp(pattern.source, 'g');
                let match;
                while ((match = regex.exec(text)) !== null) {
                    const matchText = match[0];
                    const matchIndex = match.index;
                    const before = text[matchIndex - 1];
                    const after = text[matchIndex + matchText.length];
                    
                    // Check if it's at word boundaries (more suspicious) vs inside a word
                    const beforeIsWordChar = before && /\w/.test(before);
                    const afterIsWordChar = after && /\w/.test(after);
                    
                    // If it's standalone or at word boundaries, it's suspicious
                    // If it's inside a word, it's likely part of legitimate text
                    if (!beforeIsWordChar && !afterIsWordChar) {
                        if (this.config.debug) {
                            console.log(`Suspicious pattern matched (standalone): ${matchText}`);
                        }
                        return true;
                    }
                }
            }
            
            return false;
        }
        
        // For non-description fields, use original logic
        for (let pattern of this.config.suspiciousPatterns) {
            if (pattern.test(text)) {
                if (this.config.debug) {
                    console.log(`Suspicious pattern matched in: ${text.substring(0, 50)}`);
                }
                return true;
            }
        }
        
        return false;
    }

    /**
     * Validate phone number format (basic client-side validation)
     */
    isValidPhone(phone) {
        if (!phone || !this.config.validatePhone) return true;
        
        // Remove common formatting characters
        const cleaned = phone.replace(/[\s\-\(\)\+]/g, '');
        
        // Check if it's all digits and reasonable length
        if (!/^\d+$/.test(cleaned)) return false;
        if (cleaned.length < 10 || cleaned.length > 15) return false;
        
        return true;
    }

    /**
     * Validate phone number with area code checking (client-side only)
     * Returns a Promise that resolves to {valid: boolean, details: object}
     */
    async validatePhoneWithAPI(phone) {
        if (!phone || !this.config.validatePhone) {
            return { valid: true, details: null };
        }

        // Simulate async for consistency
        await new Promise(resolve => setTimeout(resolve, 50));

        // Clean phone number
        const cleaned = phone.replace(/[\s\-\(\)\+]/g, '');
        
        // First check basic validation
        if (!this.isValidPhone(phone) || this.isSuspiciousPhone(phone)) {
            return {
                valid: false,
                details: { method: 'format_check', reason: 'Invalid format or suspicious pattern' }
            };
        }

        // Enhanced validation with area code checking
        return this.validatePhoneWithAreaCode(phone, cleaned);
    }

    /**
     * Validate phone number with area code validation
     */
    validatePhoneWithAreaCode(phone, cleaned) {
        const results = {
            valid: true,
            details: {
                method: 'enhanced_client_validation',
                format_valid: true,
                suspicious: false,
                area_code: null,
                area_code_valid: false,
                country_code: null,
                line_type: null
            }
        };

        // Extract area code for US/Canadian numbers
        let areaCode = null;
        let countryCode = null;

        if (cleaned.length === 11 && cleaned.startsWith('1')) {
            // US/CA format with country code: 1XXXXXXXXXX
            countryCode = 'US/CA';
            areaCode = cleaned.substring(1, 4);
        } else if (cleaned.length === 10) {
            // US/CA format without country code: XXXXXXXXXX
            countryCode = 'US/CA (assumed)';
            areaCode = cleaned.substring(0, 3);
        } else {
            countryCode = 'International';
        }

        results.details.country_code = countryCode;
        results.details.area_code = areaCode;

        // Validate US/Canadian area codes
        if (areaCode && countryCode && countryCode.includes('US/CA')) {
            const isValidAreaCode = this.isValidAreaCode(areaCode);
            results.details.area_code_valid = isValidAreaCode;

            if (!isValidAreaCode) {
                results.valid = false;
                results.details.reason = 'Invalid area code';
                return results;
            }

            // Estimate line type based on area code and exchange code
            const exchangeCode = cleaned.length >= 7 ? cleaned.substring(cleaned.length === 11 ? 4 : 3, cleaned.length === 11 ? 7 : 6) : null;
            results.details.line_type = this.estimateLineType(areaCode, exchangeCode);
        }

        return results;
    }

    /**
     * Check if area code is valid (US/Canadian area codes)
     */
    isValidAreaCode(areaCode) {
        if (!areaCode || areaCode.length !== 3) {
            return false;
        }

        // Area codes cannot start with 0 or 1
        if (areaCode[0] === '0' || areaCode[0] === '1') {
            return false;
        }

        // Second digit cannot be 9 (reserved for future use)
        // Actually, some area codes do have 9 as second digit, so we'll allow it

        // Valid US/Canadian area codes (simplified check)
        // In reality, there are hundreds of valid area codes
        // This checks for common patterns and excludes obviously invalid ones
        
        // Area codes: NXX format where N = 2-9, X = 0-9
        // But second digit cannot be 9 in some cases (simplified)
        
        const firstDigit = parseInt(areaCode[0]);
        const secondDigit = parseInt(areaCode[1]);
        const thirdDigit = parseInt(areaCode[2]);

        // First digit must be 2-9
        if (firstDigit < 2 || firstDigit > 9) {
            return false;
        }

        // Check for invalid patterns
        // Area codes like 911, 411, 555 (test numbers) are technically valid but suspicious
        if (areaCode === '555') {
            // 555 is reserved for fictional use, but technically valid
            return true; // Allow it but mark as suspicious elsewhere
        }

        // Check for obviously fake patterns (all same digits already caught by suspicious check)
        // But validate format: NXX where N=2-9
        return true; // Format is valid, specific validity would require a full database
    }

    /**
     * Estimate line type based on area code and exchange code
     */
    estimateLineType(areaCode, exchangeCode) {
        if (!areaCode) return 'unknown';

        // Mobile area codes (common ones - not exhaustive)
        const mobileAreaCodes = [
            '201', '202', '203', '205', '206', '207', '208', '209', '210',
            '212', '213', '214', '215', '216', '217', '218', '219', '224',
            '225', '226', '228', '229', '231', '234', '239', '240', '248',
            '251', '252', '253', '254', '256', '260', '262', '267', '269',
            '270', '272', '274', '276', '281', '283', '301', '302', '303',
            '304', '305', '307', '308', '309', '310', '312', '313', '314',
            '315', '316', '317', '318', '319', '320', '321', '323', '325',
            '326', '327', '330', '331', '332', '334', '336', '337', '339',
            '340', '341', '343', '345', '346', '347', '351', '352', '360',
            '361', '364', '365', '369', '380', '385', '386', '401', '402',
            '403', '404', '405', '406', '407', '408', '409', '410', '412',
            '413', '414', '415', '416', '417', '418', '419', '423', '424',
            '425', '430', '431', '432', '434', '435', '437', '438', '440',
            '441', '442', '443', '445', '447', '448', '450', '451', '458',
            '463', '464', '468', '469', '470', '475', '478', '479', '480',
            '484', '501', '502', '503', '504', '505', '507', '508', '509',
            '510', '512', '513', '514', '515', '516', '517', '518', '520',
            '530', '531', '534', '539', '540', '541', '551', '557', '559',
            '561', '562', '563', '564', '567', '570', '571', '572', '573',
            '574', '575', '580', '585', '586', '587', '601', '602', '603',
            '605', '606', '607', '608', '609', '610', '612', '613', '614',
            '615', '616', '617', '618', '619', '620', '623', '626', '628',
            '629', '630', '631', '636', '640', '641', '646', '647', '650',
            '651', '657', '660', '661', '662', '667', '669', '670', '671',
            '678', '679', '680', '681', '682', '684', '689', '701', '702',
            '703', '704', '705', '706', '707', '708', '712', '713', '714',
            '715', '716', '717', '718', '719', '720', '721', '724', '725',
            '726', '727', '731', '732', '734', '737', '740', '743', '747',
            '754', '757', '758', '760', '762', '763', '764', '765', '767',
            '769', '770', '771', '772', '773', '774', '775', '778', '779',
            '780', '781', '782', '784', '785', '786', '787', '801', '802',
            '803', '804', '805', '806', '807', '808', '809', '810', '812',
            '813', '814', '815', '816', '817', '818', '819', '820', '825',
            '826', '828', '829', '830', '831', '832', '838', '839', '840',
            '843', '845', '847', '848', '849', '850', '854', '856', '857',
            '858', '859', '860', '862', '863', '864', '865', '867', '868',
            '869', '870', '872', '873', '878', '901', '902', '903', '904',
            '906', '907', '908', '909', '910', '912', '913', '914', '915',
            '916', '917', '918', '919', '920', '925', '928', '929', '930',
            '931', '934', '935', '936', '937', '938', '939', '940', '941',
            '943', '945', '947', '948', '949', '951', '952', '954', '956',
            '959', '970', '971', '972', '973', '975', '978', '979', '980',
            '984', '985', '986', '989'
        ];

        // Check if area code is commonly mobile
        if (mobileAreaCodes.includes(areaCode)) {
            return 'possibly_mobile';
        }

        // Exchange code patterns (middle 3 digits)
        // Exchange codes starting with certain numbers are more likely mobile
        if (exchangeCode) {
            const exchangeFirst = parseInt(exchangeCode[0]);
            // Modern mobile numbers often have exchange codes starting with 2-9
            // But this is not definitive
        }

        return 'unknown';
    }

    /**
     * Enhanced phone validation with suspicious pattern detection
     */
    isSuspiciousPhone(phone) {
        if (!phone || !this.config.validatePhone) return false;
        
        const cleaned = phone.replace(/[\s\-\(\)\+]/g, '');
        
        // Check for suspicious patterns
        // All same digits (e.g., 1111111111)
        if (/^(\d)\1{9,}$/.test(cleaned)) {
            return true;
        }
        
        // Sequential digits (e.g., 1234567890)
        if (/0123456789|1234567890|9876543210|0987654321/.test(cleaned)) {
            return true;
        }
        
        // Repeated patterns (e.g., 1212121212)
        if (/^(\d{2,})\1{4,}$/.test(cleaned)) {
            return true;
        }
        
        return false;
    }

    /**
     * Validate website URL
     */
    isValidWebsite(website) {
        if (!website || !this.config.validateWebsite) return true;
        
        // Check if it's a random string (high entropy)
        if (this.isRandomString(website)) {
            return false;
        }
        
        // Basic URL format check
        try {
            // If it doesn't start with http/https, add it for validation
            const urlToCheck = website.startsWith('http') ? website : `https://${website}`;
            new URL(urlToCheck);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Validate a single field
     */
    validateField(fieldName, value, fieldType = 'text') {
        const issues = [];
        
        if (!value || value.trim().length === 0) {
            return { valid: true, issues: [] }; // Empty fields handled by required validation
        }
        
        const trimmedValue = value.trim();
        
        switch (fieldType.toLowerCase()) {
            case 'name':
                if (this.isRandomString(trimmedValue)) {
                    issues.push('Name appears to be random characters');
                }
                if (this.matchesSuspiciousPatterns(trimmedValue)) {
                    issues.push('Name contains suspicious patterns');
                }
                break;
                
            case 'email':
                if (this.isSuspiciousEmail(trimmedValue)) {
                    issues.push('Email appears suspicious');
                }
                break;
                
            case 'phone':
                if (!this.isValidPhone(trimmedValue)) {
                    issues.push('Invalid phone number format');
                }
                if (this.isSuspiciousPhone(trimmedValue)) {
                    issues.push('Phone number appears suspicious');
                }
                break;
                
            case 'website':
            case 'url':
                if (!this.isValidWebsite(trimmedValue)) {
                    issues.push('Invalid or suspicious website URL');
                }
                break;
                
            case 'description':
            case 'message':
                // Special handling for description/message fields
                // Check for random strings (with description-aware logic)
                if (this.isRandomString(trimmedValue, true)) {
                    // Only flag if it doesn't contain actual words
                    if (!this.containsActualWords(trimmedValue)) {
                        issues.push('Content appears to be random characters');
                    }
                }
                // Check for spam keywords
                if (this.containsSpamKeywords(trimmedValue)) {
                    issues.push('Content contains spam keywords');
                }
                // Check for suspicious patterns (with description-aware logic)
                if (this.matchesSuspiciousPatterns(trimmedValue, true)) {
                    issues.push('Content matches suspicious patterns');
                }
                break;
                
            case 'text':
            default:
                // For generic text fields, use standard validation
                if (this.isRandomString(trimmedValue)) {
                    issues.push('Content appears to be random characters');
                }
                if (this.containsSpamKeywords(trimmedValue)) {
                    issues.push('Content contains spam keywords');
                }
                if (this.matchesSuspiciousPatterns(trimmedValue)) {
                    issues.push('Content matches suspicious patterns');
                }
                break;
        }
        
        // Run custom validators
        for (let validator of this.config.customValidators) {
            const result = validator(fieldName, trimmedValue, fieldType);
            if (result && result.valid === false) {
                issues.push(result.message || 'Custom validation failed');
            }
        }
        
        return {
            valid: issues.length === 0,
            issues: issues
        };
    }

    /**
     * Validate entire form data
     */
    validateForm(formData) {
        const results = {
            valid: true,
            fields: {},
            issues: []
        };
        
        for (let fieldName in formData) {
            const value = formData[fieldName];
            
            // Infer field type from name or treat as text
            let fieldType = 'text';
            const lowerName = fieldName.toLowerCase();
            if (lowerName.includes('name')) fieldType = 'name';
            else if (lowerName.includes('email')) fieldType = 'email';
            else if (lowerName.includes('phone') || lowerName.includes('tel')) fieldType = 'phone';
            else if (lowerName.includes('website') || lowerName.includes('url')) fieldType = 'website';
            else if (lowerName.includes('description') || lowerName.includes('message')) fieldType = 'description';
            
            const validation = this.validateField(fieldName, value, fieldType);
            results.fields[fieldName] = validation;
            
            if (!validation.valid) {
                results.valid = false;
                results.issues.push(...validation.issues.map(issue => `${fieldName}: ${issue}`));
            }
        }
        
        return results;
    }

    /**
     * Check if form submission is spam
     */
    isSpam(formData) {
        const validation = this.validateForm(formData);
        
        if (this.config.debug) {
            console.log('Form validation result:', validation);
        }
        
        return !validation.valid;
    }
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AntiFormSpam;
}

// Also make available globally
if (typeof window !== 'undefined') {
    window.AntiFormSpam = AntiFormSpam;
}

