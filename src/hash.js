'use strict';

// Original source at https://github.com/elasticio/node-ntlm-client/blob/master/lib/hash.js

const crypto = require('crypto');
const desjs = require('des.js');
const md4 = require('js-md4');

function createLMResponse(challenge, lmhash) {
	let buf = new Buffer.alloc(24),
		pwBuffer = new Buffer.alloc(21).fill(0);

	lmhash.copy(pwBuffer);

	calculateDES(pwBuffer.slice(0, 7), challenge).copy(buf);
	calculateDES(pwBuffer.slice(7, 14), challenge).copy(buf, 8);
	calculateDES(pwBuffer.slice(14), challenge).copy(buf, 16);

	return buf;
}

function createLMHash(password) {
	let buf = new Buffer.alloc(16),
		pwBuffer = new Buffer.alloc(14),
		magicKey = new Buffer.from('KGS!@#$%', 'ascii');

	if (password.length > 14) {
		buf.fill(0);
		return buf;
	}

	pwBuffer.fill(0);
	pwBuffer.write(password.toUpperCase(), 0, 'ascii');

	return Buffer.concat([
		calculateDES(pwBuffer.slice(0, 7), magicKey),
		calculateDES(pwBuffer.slice(7), magicKey)
	]);
}

function calculateDES(key, message) {
	let desKey = new Buffer.alloc(8);

	desKey[0] = key[0] & 0xFE;
	desKey[1] = ((key[0] << 7) & 0xFF) | (key[1] >> 1);
	desKey[2] = ((key[1] << 6) & 0xFF) | (key[2] >> 2);
	desKey[3] = ((key[2] << 5) & 0xFF) | (key[3] >> 3);
	desKey[4] = ((key[3] << 4) & 0xFF) | (key[4] >> 4);
	desKey[5] = ((key[4] << 3) & 0xFF) | (key[5] >> 5);
	desKey[6] = ((key[5] << 2) & 0xFF) | (key[6] >> 6);
	desKey[7] = (key[6] << 1) & 0xFF;

	for (let i = 0; i < 8; i++) {
		let parity = 0;

		for (let j = 1; j < 8; j++) {
			parity += (desKey[i] >> j) % 2;
		}

		desKey[i] |= (parity % 2) === 0 ? 1 : 0;
	}

	const des = desjs.DES.create({ type: 'encrypt', key: desKey });
	return des.update(message);
}

function createNTLMResponse(challenge, ntlmhash) {
	let buf = new Buffer.alloc(24),
		ntlmBuffer = new Buffer.alloc(21).fill(0);

	ntlmhash.copy(ntlmBuffer);

	calculateDES(ntlmBuffer.slice(0, 7), challenge).copy(buf);
	calculateDES(ntlmBuffer.slice(7, 14), challenge).copy(buf, 8);
	calculateDES(ntlmBuffer.slice(14), challenge).copy(buf, 16);

	return buf;
}

function createNTLMHash(password) {
	let md4sum = md4.create();
	md4sum.update(new Buffer.from(password, 'ucs2'));
	return Buffer.from(md4sum.buffer());
}

function createNTLMv2Hash(ntlmhash, username, authTargetName) {
	let hmac = crypto.createHmac('md5', ntlmhash);
	hmac.update(new Buffer.from(username.toUpperCase() + authTargetName, 'ucs2'));
	return hmac.digest();
}

function createLMv2Response(type2message, username, ntlmhash, nonce, targetName) {
	let buf = new Buffer.alloc(24),
		ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName),
		hmac = crypto.createHmac('md5', ntlm2hash);

	//server challenge
	type2message.challenge.copy(buf, 8);

	//client nonce
	buf.write(nonce || createPseudoRandomValue(16), 16, 'hex');

	//create hash
	hmac.update(buf.slice(8));
	let hashedBuffer = hmac.digest();

	hashedBuffer.copy(buf);

	return buf;
}

function createFileTimestamp(serverTimestamp) {
	// Reuse the server-provided FILETIME when available (avoids clock-skew rejections on strict servers).
	if (serverTimestamp) {
		return serverTimestamp;
	}

	// FILETIME = 100ns intervals since 1601-01-01; 11644473600000 = ms between 1601 and 1970.
	// Using BigInt avoids the precision loss of the old Number-based hex split.
	let filetime = (BigInt(Date.now()) + 11644473600000n) * 10000n;
	let buf = new Buffer.alloc(8);
	buf.writeBigUInt64LE(filetime, 0);
	return buf;
}

function appendAvPair(targetInfoBuffer, avId, value) {
	// Splice a new AV_PAIR in before the terminating MsvAvEOL (type 0, length 0) pair.
	let header = new Buffer.alloc(4);
	header.writeUInt16LE(avId, 0);
	header.writeUInt16LE(value.length, 2);

	let eol = new Buffer.alloc(4);

	return Buffer.concat([
		targetInfoBuffer.slice(0, Math.max(0, targetInfoBuffer.length - 4)),
		header,
		value,
		eol
	]);
}

function createNTLMv2Response(type2message, username, ntlmhash, nonce, targetName, options) {
	options = options || {};

	let targetInfoBuffer = type2message.targetInfo.buffer;

	if (options.channelBindingValue) {
		targetInfoBuffer = appendAvPair(targetInfoBuffer, 0x0A, options.channelBindingValue);
	}

	let buf = new Buffer.alloc(48 + targetInfoBuffer.length),
		ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName),
		hmac = crypto.createHmac('md5', ntlm2hash);

	//the first 16 bytes are spare to store the hashed value before the blob

	//server challenge
	type2message.challenge.copy(buf, 8);

	//blob signature
	buf.writeUInt32BE(0x01010000, 16);

	//reserved
	buf.writeUInt32LE(0, 20);

	//timestamp
	createFileTimestamp(options.serverTimestamp).copy(buf, 24);

	//random client nonce
	buf.write(nonce || createPseudoRandomValue(16), 32, 'hex');

	//zero
	buf.writeUInt32LE(0, 40);

	//complete target information block from type 2 message (plus any client-added AV pairs)
	targetInfoBuffer.copy(buf, 44);

	//zero
	buf.writeUInt32LE(0, 44 + targetInfoBuffer.length);

	hmac.update(buf.slice(8));
	let hashedBuffer = hmac.digest();

	hashedBuffer.copy(buf);

	return buf;
}

function createSessionBaseKey(ntlmhash, username, targetName, ntProofStr) {
	let ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName);
	return crypto.createHmac('md5', ntlm2hash).update(ntProofStr).digest();
}

function createMessageIntegrityCode(sessionBaseKey, type1Buffer, type2Buffer, type3Buffer) {
	return crypto.createHmac('md5', sessionBaseKey)
		.update(Buffer.concat([type1Buffer, type2Buffer, type3Buffer]))
		.digest();
}

function createChannelBindingHash(certificateDer) {
	// Simplified per RFC 5929 4.1: SHA-256 covers the signature algorithm of the vast majority of certificates in practice.
	let certHash = crypto.createHash('sha256').update(certificateDer).digest();
	let applicationData = Buffer.concat([new Buffer.from('tls-server-end-point:', 'ascii'), certHash]);

	//gss_channel_bindings_struct with empty initiator/acceptor addresses
	let struct = new Buffer.alloc(20 + applicationData.length);
	struct.writeUInt32LE(applicationData.length, 16);
	applicationData.copy(struct, 20);

	return crypto.createHash('md5').update(struct).digest();
}

function createPseudoRandomValue(length) {
	let str = '';
	while (str.length < length) {
		str += Math.floor(Math.random() * 16).toString(16);
	}
	return str;
}

module.exports = {
	createLMHash,
	createNTLMHash,
	createLMResponse,
	createNTLMResponse,
	createLMv2Response,
	createNTLMv2Response,
	createSessionBaseKey,
	createMessageIntegrityCode,
	createChannelBindingHash,
	createPseudoRandomValue
};
