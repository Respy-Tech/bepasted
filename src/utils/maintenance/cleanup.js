import { Paste, ArchivedPaste } from '../../models/paste.js';
import config from '../../utils/config/config.js';

// Function to find expired pastes
async function findExpiredPastes() {
    const timeExpiredPastes = await Paste.find({
        'expiry.expiresAt': { $lt: new Date() },
        isExpired: false
    });

    const viewExpiredPastes = await Paste.find({
        burnCount: { $exists: true },
        $expr: { $gte: ['$currentViews', '$burnCount'] },
        isExpired: false
    });

    return [...timeExpiredPastes, ...viewExpiredPastes];
}

// Function to create archive data from paste
function createArchiveData(paste) {
    const archiveData = {
        originalId: paste.id,
        tabs: paste.tabs,
        isPrivate: paste.isPrivate,
        allowRaw: paste.allowRaw,
        burnCount: paste.burnCount,
        finalViews: paste.currentViews,
        createdAt: paste.createdAt,
        expiredAt: new Date(),
        expiryReason: paste.expiry?.expiresAt && Date.now() > paste.expiry.expiresAt ? 'time' : 'views'
    };

    const hasValidExpiry = paste.expiry && 
        'value' in paste.expiry &&
        'unit' in paste.expiry &&
        'expiresAt' in paste.expiry;

    if (hasValidExpiry) {
        archiveData.expiry = {
            value: paste.expiry.value,
            unit: paste.expiry.unit,
            expiresAt: paste.expiry.expiresAt
        };
    }

    return archiveData;
}

// Function to archive a single paste
async function archivePaste(paste) {
    paste.isExpired = true;
    await paste.save();
    
    const archiveData = createArchiveData(paste);
    const archive = new ArchivedPaste(archiveData);
    
    await archive.save();
    await paste.deleteOne();
}

// Function to clean up old archives
async function cleanupOldArchives() {
    // Default archive retention is 3 months (90 days), but use ARCHIVE_RETENTION_DAYS if set
    const archiveRetentionDays = config.ARCHIVE_RETENTION_DAYS || 90;
    const archiveRetentionDate = new Date();
    archiveRetentionDate.setDate(archiveRetentionDate.getDate() - archiveRetentionDays);
    
    await ArchivedPaste.deleteMany({
        expiredAt: { $lt: archiveRetentionDate }
    });
}

// Main cleanup function
async function cleanupExpiredPastes() {
    try {
        const expiredPastes = await findExpiredPastes();
        
        for (const paste of expiredPastes) {
            await archivePaste(paste);
        }

        await cleanupOldArchives();
        console.log(`Cleaned up ${expiredPastes.length} expired pastes`);
    } catch (error) {
        console.error('Error during cleanup:', error);
    }
}

// Setup cleanup scheduler
export function setupCleanupScheduler() {
    // Run cleanup on startup
    cleanupExpiredPastes();
    
    // Schedule cleanup every hour
    setInterval(cleanupExpiredPastes, 60 * 60 * 1000);
}
