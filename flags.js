'use strict';

const crypto = require('crypto');

const FLAG_PATTERN = /^CTF\{d1_([a-z0-9]{1,12})_([a-f0-9]{32})\}$/;

function positiveInteger(value, name, { allowZero = false } = {}) {
    const number = Number(value);
    const minimum = allowZero ? 0 : 1;
    if (!Number.isSafeInteger(number) || number < minimum) {
        throw new Error(`${name} must be a ${allowZero ? 'non-negative' : 'positive'} integer`);
    }
    return number;
}

function loadDynamicFlagConfig(env = process.env) {
    const currentKeyId = String(env.DYNAMIC_FLAG_CURRENT_KEY || '').trim().toLowerCase();
    if (!/^[a-z0-9]{1,12}$/.test(currentKeyId)) {
        throw new Error('DYNAMIC_FLAG_CURRENT_KEY must contain 1-12 lowercase letters or digits');
    }

    const keys = new Map();
    for (const [name, rawValue] of Object.entries(env)) {
        const match = /^DYNAMIC_FLAG_KEY_([A-Z0-9]{1,12})$/.exec(name);
        if (!match || !rawValue) continue;
        const keyId = match[1].toLowerCase();
        const encoded = String(rawValue).trim();
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) {
            throw new Error(`${name} must be a base64-encoded secret`);
        }
        const key = Buffer.from(encoded, 'base64');
        if (key.length < 32) throw new Error(`${name} must decode to at least 32 bytes`);
        keys.set(keyId, key);
    }

    if (!keys.has(currentKeyId)) {
        throw new Error(`DYNAMIC_FLAG_KEY_${currentKeyId.toUpperCase()} is missing`);
    }
    return Object.freeze({ currentKeyId, keys });
}

function canonicalPayload({ userId, challengeId, eventId = 0 }, keyId) {
    return JSON.stringify([
        'ctf-square-review',
        1,
        keyId,
        positiveInteger(userId, 'userId'),
        positiveInteger(challengeId, 'challengeId'),
        positiveInteger(eventId, 'eventId', { allowZero: true })
    ]);
}

function computeTag(context, keyId, key) {
    return crypto
        .createHmac('sha256', key)
        .update(canonicalPayload(context, keyId), 'utf8')
        .digest()
        .subarray(0, 16);
}

function createDynamicFlag(context, config = loadDynamicFlagConfig()) {
    const keyId = config.currentKeyId;
    const key = config.keys.get(keyId);
    if (!key) throw new Error(`Dynamic flag key ${keyId} is unavailable`);
    return `CTF{d1_${keyId}_${computeTag(context, keyId, key).toString('hex')}}`;
}

function verifyDynamicFlag(submittedFlag, context, config = loadDynamicFlagConfig()) {
    if (typeof submittedFlag !== 'string') return false;
    const match = FLAG_PATTERN.exec(submittedFlag.trim());
    if (!match) return false;

    const [, keyId, submittedHex] = match;
    const key = config.keys.get(keyId);
    if (!key) return false;

    const submittedTag = Buffer.from(submittedHex, 'hex');
    const expectedTag = computeTag(context, keyId, key);
    return submittedTag.length === expectedTag.length
        && crypto.timingSafeEqual(submittedTag, expectedTag);
}

module.exports = {
    FLAG_PATTERN,
    loadDynamicFlagConfig,
    createDynamicFlag,
    verifyDynamicFlag
};
