import mongoose from 'mongoose';
const { Schema, model } = mongoose;

const reportedPasteSchema = new Schema({
    pasteId: {
        type: String,
        required: true,
        index: true
    },
    reason: {
        type: String,
        required: true
    },
    reporterIp: {
        type: String,
        required: true
    },
    reportDate: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['pending', 'reviewed', 'dismissed'],
        default: 'pending'
    },
    // Reference to the paste in question
    pasteData: {
        pasteId: String,
        content: String,
        isPrivate: Boolean,
        isExpired: Boolean,
        creatorIp: String,
        createdAt: Date
    }
});

// Create a compound index for pasteId and reporterIp to prevent duplicate reports
reportedPasteSchema.index({ pasteId: 1, reporterIp: 1 }, { unique: true });

export const ReportedPaste = model('ReportedPaste', reportedPasteSchema, 'reportedpastes'); 