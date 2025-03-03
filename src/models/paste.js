import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import IPAnonymizer from '../utils/security/ip-anonymizer.js';
import config from '../utils/config/config.js';

const tabSchema = new mongoose.Schema({
    id: {
        type: Number,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    content: {
        type: String,
        required: true,
        validate: [
            {
                validator: function(v) {
                    return v && v.trim().length > 0;
                },
                message: 'Content cannot be empty'
            },
            {
                validator: function(v) {
                    // Check if content size is within 2MB limit
                    // Using Buffer.byteLength to get actual byte size
                    return Buffer.byteLength(v, 'utf8') <= 2 * 1024 * 1024;
                },
                message: 'Content size exceeds 2MB limit'
            }
        ]
    }
});

const pasteSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    tabs: {
        type: [tabSchema],
        required: true,
        validate: [
            {
                validator: function(tabs) {
                    return tabs && tabs.length > 0 && tabs.some(tab => tab.content && tab.content.trim().length > 0);
                },
                message: 'At least one tab must have content'
            },
            {
                validator: function(tabs) {
                    return tabs && tabs.length <= 10;
                },
                message: 'Maximum of 10 tabs allowed'
            }
        ]
    },
    isPrivate: {
        type: Boolean,
        default: false
    },
    password: {
        type: String,
        validate: {
            validator: function(password) {
                if (!this.isPrivate) return true;
                if (!password) return false;
                return password.length >= 1 && password.length <= 32;
            },
            message: 'Password must be between 1 and 32 characters long'
        }
    },
    allowRaw: {
        type: Boolean,
        default: false
    },
    expiry: {
        type: new mongoose.Schema({
            value: {
                type: Number,
                required: true,
                min: 1
            },
            unit: {
                type: String,
                required: true,
                enum: ['seconds', 'minutes', 'hours', 'days']
            },
            expiresAt: {
                type: Date,
                required: true
            }
        }, { _id: false }),
        required: false,
        validate: {
            validator: function(v) {
                // If expiry is not provided at all, that's valid
                if (!v) return true;
                
                // If expiry is provided, all fields must be valid
                return (
                    typeof v.value === 'number' && 
                    v.value > 0 &&
                    typeof v.unit === 'string' && 
                    ['seconds', 'minutes', 'hours', 'days'].includes(v.unit) &&
                    v.expiresAt instanceof Date
                );
            },
            message: 'Expiry must have valid value, unit, and expiresAt fields'
        }
    },
    burnCount: {
        type: Number,
        min: 1,
        max: 10000000000
    },
    currentViews: {
        type: Number,
        default: 0,
        min: 0
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true
    },
    creatorIp: {
        type: String,
        required: true
    },
    anonymizedCreatorIp: {
        type: String,
        required: true
    },
    createdFromRegion: {
        type: String,
        required: false
    },
    isExpired: {
        type: Boolean,
        default: false,
        index: true
    },
    dataRetentionDate: {
        type: Date,
        required: true
    }
});

// Hash password before saving
pasteSchema.pre('save', async function(next) {
    if (this.isModified('password') && this.password) {
        const SALT_ROUNDS = 12; 
        this.password = await bcrypt.hash(this.password, SALT_ROUNDS);
    }
    next();
});

// Anonymize IP address before saving
pasteSchema.pre('save', function(next) {
    // For new documents or when creatorIp is modified, or when required fields are missing
    if (this.isNew || this.isModified('creatorIp') || !this.anonymizedCreatorIp || !this.dataRetentionDate) {
        // Fully anonymized version for long-term storage
        this.anonymizedCreatorIp = this.anonymizedCreatorIp || IPAnonymizer.anonymizeIP(this.creatorIp);
        
        // Set data retention date (configurable days from creation by default)
        if (!this.dataRetentionDate) {
            const retentionPeriod = config.DATA_RETENTION_DAYS * 24 * 60 * 60 * 1000; // Convert days to milliseconds
            this.dataRetentionDate = new Date(Date.now() + retentionPeriod);
        }
    }
    next();
});

// Calculate expiry date before saving
pasteSchema.pre('save', function(next) {
    // Only try to calculate expiry if all required fields are present
    if (this.expiry && 
        typeof this.expiry.value === 'number' && 
        this.expiry.value > 0 &&
        typeof this.expiry.unit === 'string' && 
        ['seconds', 'minutes', 'hours', 'days'].includes(this.expiry.unit)) {
        
        const multipliers = {
            seconds: 1000,
            minutes: 60 * 1000,
            hours: 60 * 60 * 1000,
            days: 24 * 60 * 60 * 1000
        };
        
        this.expiry.expiresAt = new Date(
            Date.now() + (this.expiry.value * multipliers[this.expiry.unit])
        );
    }
    next();
});

// Method to verify password
pasteSchema.methods.verifyPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

// Method to check if paste is expired
pasteSchema.methods.checkExpiry = function() {
    if (this.isExpired) return true;
    
    if (this.expiry?.expiresAt && Date.now() > this.expiry.expiresAt) {
        this.isExpired = true;
        return true;
    }
    
    if (this.burnCount && this.currentViews >= this.burnCount) {
        this.isExpired = true;
        return true;
    }
    
    return false;
};

export const Paste = mongoose.model('Paste', pasteSchema);

// Create Archive model for expired pastes
const archiveSchema = new mongoose.Schema({
    originalId: {
        type: String,
        required: true,
        index: true
    },
    tabs: [tabSchema],
    isPrivate: Boolean,
    allowRaw: Boolean,
    expiry: {
        value: Number,
        unit: {
            type: String,
            enum: ['seconds', 'minutes', 'hours', 'days']
        },
        expiresAt: Date
    },
    burnCount: Number,
    finalViews: {
        type: Number,
        required: true
    },
    createdAt: {
        type: Date,
        required: true
    },
    expiredAt: {
        type: Date,
        required: true,
        index: true
    },
    expiryReason: {
        type: String,
        enum: ['time', 'views', 'manual'],
        required: true
    }
});

export const ArchivedPaste = mongoose.model('ArchivedPaste', archiveSchema);
