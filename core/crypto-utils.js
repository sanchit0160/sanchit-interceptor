/**
 * Sanchit Interceptor — Crypto & Decoder Utilities
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Powers the Decoder & JWT tool:
 * - URL, Base64, Hex, HTML entity encoding/decoding
 * - Deep JWT inspection & expiration analysis
 * - Cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512)
 * - Smart format auto-detection
 */

// ============================================================
// Encoding & Decoding
// ============================================================

export function urlEncode(str, componentOnly = false) {
  if (!str) return '';
  return componentOnly ? encodeURIComponent(str) : encodeURI(str);
}

export function urlDecode(str) {
  if (!str) return '';
  try {
    return decodeURIComponent(str.replace(/\+/g, ' '));
  } catch (e) {
    return unescape(str);
  }
}

export function base64Encode(str) {
  if (!str) return '';
  try {
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binStr = '';
    for (let i = 0; i < bytes.length; i++) {
      binStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binStr);
  } catch (e) {
    return btoa(unescape(encodeURIComponent(str)));
  }
}

export function base64Decode(str) {
  if (!str) return '';
  const cleaned = str.trim().replace(/\s+/g, '');
  try {
    const binStr = atob(cleaned);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    const decoder = new TextDecoder('utf-8', { fatal: false });
    return decoder.decode(bytes);
  } catch (e) {
    throw new Error('Invalid Base64 string: ' + e.message);
  }
}

export function hexEncode(str, delimiter = ' ') {
  if (!str) return '';
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const hex = [];
  for (let i = 0; i < bytes.length; i++) {
    hex.push(bytes[i].toString(16).padStart(2, '0'));
  }
  return hex.join(delimiter);
}

export function hexDecode(hexStr) {
  if (!hexStr) return '';
  const cleaned = hexStr.replace(/[^0-9a-fA-F]/g, '');
  if (cleaned.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters');
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substr(i, 2), 16);
  }
  const decoder = new TextDecoder('utf-8', { fatal: false });
  return decoder.decode(bytes);
}

export function htmlEncode(str) {
  if (!str) return '';
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[m]));
}

export function htmlDecode(str) {
  if (!str) return '';
  if (typeof document !== 'undefined') {
    const txt = document.createElement('textarea');
    txt.innerHTML = str;
    return txt.value;
  }
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#([0-9]+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)));
}

// ============================================================
// JWT Inspector
// ============================================================

export function inspectJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.trim().split('.');
  if (parts.length !== 3) return null;

  try {
    const decodePart = p => {
      // Add base64 padding
      let base64 = p.replace(/-/g, '+').replace(/_/g, '/');
      while (base64.length % 4) base64 += '=';
      const json = base64Decode(base64);
      return JSON.parse(json);
    };

    const header = decodePart(parts[0]);
    const payload = decodePart(parts[1]);
    const signature = parts[2];

    const claims = {};
    const nowSec = Math.floor(Date.now() / 1000);

    if (payload.exp) {
      const expDate = new Date(payload.exp * 1000);
      const isExpired = payload.exp < nowSec;
      const diffSec = Math.abs(payload.exp - nowSec);
      const diffMin = Math.round(diffSec / 60);
      claims.expiration = {
        timestamp: payload.exp,
        iso: expDate.toISOString(),
        isExpired,
        description: isExpired ? `Expired ${diffMin} min ago` : `Expires in ${diffMin} min`,
      };
    }

    if (payload.iat) {
      claims.issuedAt = {
        timestamp: payload.iat,
        iso: new Date(payload.iat * 1000).toISOString(),
      };
    }

    return {
      isValidJwt: true,
      header,
      payload,
      signature,
      claims,
      algorithm: header.alg || 'unknown',
      type: header.typ || 'JWT',
    };
  } catch (e) {
    return null;
  }
}

// ============================================================
// Cryptographic Hashes
// ============================================================

export async function computeHash(algorithm, text) {
  if (!text) return '';
  const algo = algorithm.toUpperCase();

  if (algo === 'MD5') {
    return md5(text);
  }

  const validWebCrypto = ['SHA-1', 'SHA-256', 'SHA-512', 'SHA-384'];
  if (!validWebCrypto.includes(algo)) {
    throw new Error('Unsupported hash algorithm: ' + algorithm);
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest(algo, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Pure JavaScript MD5 Implementation
 */
export function md5(string) {
  function md5_RotateLeft(lValue, iShiftBits) {
    return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
  }
  function md5_AddUnsigned(lX, lY) {
    const lX4 = lX & 0x40000000;
    const lY4 = lY & 0x40000000;
    const lX8 = lX & 0x80000000;
    const lY8 = lY & 0x80000000;
    const lResult = (lX & 0x3fffffff) + (lY & 0x3fffffff);
    if (lX4 & lY4) return lResult ^ 0x80000000 ^ lX8 ^ lY8;
    if (lX4 | lY4) {
      if (lResult & 0x40000000) return lResult ^ 0xc0000000 ^ lX8 ^ lY8;
      else return lResult ^ 0x40000000 ^ lX8 ^ lY8;
    } else return lResult ^ lX8 ^ lY8;
  }
  function md5_F(x, y, z) { return (x & y) | ((~x) & z); }
  function md5_G(x, y, z) { return (x & z) | (y & (~z)); }
  function md5_H(x, y, z) { return (x ^ y ^ z); }
  function md5_I(x, y, z) { return (y ^ (x | (~z))); }
  function md5_FF(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_F(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_GG(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_G(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_HH(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_H(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }
  function md5_II(a, b, c, d, x, s, ac) {
    a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_I(b, c, d), x), ac));
    return md5_AddUnsigned(md5_RotateLeft(a, s), b);
  }

  function md5_ConvertToWordArray(string) {
    let lWordCount;
    const lMessageLength = string.length;
    const lNumberOfWords_temp1 = lMessageLength + 8;
    const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
    const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
    const lWordArray = new Array(lNumberOfWords - 1);
    let lBytePosition = 0;
    let lByteCount = 0;
    while (lByteCount < lMessageLength) {
      lWordCount = (lByteCount - (lByteCount % 4)) / 4;
      lBytePosition = (lByteCount % 4) * 8;
      lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
      lByteCount++;
    }
    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
    lBytePosition = (lByteCount % 4) * 8;
    lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
    lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
    lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
    return lWordArray;
  }

  function md5_WordToHex(lValue) {
    let WordToHexValue = '', WordToHexValue_temp = '', lByte, lCount;
    for (lCount = 0; lCount <= 3; lCount++) {
      lByte = (lValue >>> (lCount * 8)) & 255;
      WordToHexValue_temp = '0' + lByte.toString(16);
      WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
    }
    return WordToHexValue;
  }

  const x = md5_ConvertToWordArray(string);
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
  for (let k = 0; k < x.length; k += 16) {
    const AA = a, BB = b, CC = c, DD = d;
    a = md5_FF(a, b, c, d, x[k + 0], 7, 0xd76aa478);
    d = md5_FF(d, a, b, c, x[k + 1], 12, 0xe8c7b756);
    c = md5_FF(c, d, a, b, x[k + 2], 17, 0x242070db);
    b = md5_FF(b, c, d, a, x[k + 3], 22, 0xc1bdceee);
    a = md5_FF(a, b, c, d, x[k + 4], 7, 0xf57c0faf);
    d = md5_FF(d, a, b, c, x[k + 5], 12, 0x4787c62a);
    c = md5_FF(c, d, a, b, x[k + 6], 17, 0xa8304613);
    b = md5_FF(b, c, d, a, x[k + 7], 22, 0xfd469501);
    a = md5_FF(a, b, c, d, x[k + 8], 7, 0x698098d8);
    d = md5_FF(d, a, b, c, x[k + 9], 12, 0x8b44f7af);
    c = md5_FF(c, d, a, b, x[k + 10], 17, 0xffff5bb1);
    b = md5_FF(b, c, d, a, x[k + 11], 22, 0x895cd7be);
    a = md5_FF(a, b, c, d, x[k + 12], 7, 0x6b901122);
    d = md5_FF(d, a, b, c, x[k + 13], 12, 0xfd987193);
    c = md5_FF(c, d, a, b, x[k + 14], 17, 0xa679438e);
    b = md5_FF(b, c, d, a, x[k + 15], 22, 0x49b40821);

    a = md5_GG(a, b, c, d, x[k + 1], 5, 0xf61e2562);
    d = md5_GG(d, a, b, c, x[k + 6], 9, 0xc040b340);
    c = md5_GG(c, d, a, b, x[k + 11], 14, 0x265e5a51);
    b = md5_GG(b, c, d, a, x[k + 0], 20, 0xe9b6c7aa);
    a = md5_GG(a, b, c, d, x[k + 5], 5, 0xd62f105d);
    d = md5_GG(d, a, b, c, x[k + 10], 9, 0x02441453);
    c = md5_GG(c, d, a, b, x[k + 15], 14, 0xd8a1e681);
    b = md5_GG(b, c, d, a, x[k + 4], 20, 0xe7d3fbc8);
    a = md5_GG(a, b, c, d, x[k + 9], 5, 0x21e1cde6);
    d = md5_GG(d, a, b, c, x[k + 14], 9, 0xc33707d6);
    c = md5_GG(c, d, a, b, x[k + 3], 14, 0xf4d50d87);
    b = md5_GG(b, c, d, a, x[k + 8], 20, 0x455a14ed);
    a = md5_GG(a, b, c, d, x[k + 13], 5, 0xa9e3e905);
    d = md5_GG(d, a, b, c, x[k + 2], 9, 0xfcefa3f8);
    c = md5_GG(c, d, a, b, x[k + 7], 14, 0x676f02d9);
    b = md5_GG(b, c, d, a, x[k + 12], 20, 0x8d2a4c8a);

    a = md5_HH(a, b, c, d, x[k + 5], 4, 0xfffa3942);
    d = md5_HH(d, a, b, c, x[k + 8], 11, 0x8771f681);
    c = md5_HH(c, d, a, b, x[k + 11], 16, 0x6d9d6122);
    b = md5_HH(b, c, d, a, x[k + 14], 23, 0xfde5380c);
    a = md5_HH(a, b, c, d, x[k + 1], 4, 0xa4beea44);
    d = md5_HH(d, a, b, c, x[k + 4], 11, 0x4bdecfa9);
    c = md5_HH(c, d, a, b, x[k + 7], 16, 0xf6bb4b60);
    b = md5_HH(b, c, d, a, x[k + 10], 23, 0xbebfbc70);
    a = md5_HH(a, b, c, d, x[k + 13], 4, 0x289b7ec6);
    d = md5_HH(d, a, b, c, x[k + 0], 11, 0xeaa127fa);
    c = md5_HH(c, d, a, b, x[k + 3], 16, 0xd4ef3085);
    b = md5_HH(b, c, d, a, x[k + 6], 23, 0x04881d05);
    a = md5_HH(a, b, c, d, x[k + 9], 4, 0xd9d4d039);
    d = md5_HH(d, a, b, c, x[k + 12], 11, 0xe6db99e5);
    c = md5_HH(c, d, a, b, x[k + 15], 16, 0x1fa27cf8);
    b = md5_HH(b, c, d, a, x[k + 2], 23, 0xc4ac5665);

    a = md5_II(a, b, c, d, x[k + 0], 6, 0xf4292244);
    d = md5_II(d, a, b, c, x[k + 7], 10, 0x432aff97);
    c = md5_II(c, d, a, b, x[k + 14], 15, 0xab9423a7);
    b = md5_II(b, c, d, a, x[k + 5], 21, 0xfc93a039);
    a = md5_II(a, b, c, d, x[k + 12], 6, 0x655b59c3);
    d = md5_II(d, a, b, c, x[k + 3], 10, 0x8f0ccc92);
    c = md5_II(c, d, a, b, x[k + 10], 15, 0xffeff47d);
    b = md5_II(b, c, d, a, x[k + 1], 21, 0x85845dd1);
    a = md5_II(a, b, c, d, x[k + 8], 6, 0x6fa87e4f);
    d = md5_II(d, a, b, c, x[k + 15], 10, 0xfe2ce6e0);
    c = md5_II(c, d, a, b, x[k + 6], 15, 0xa3014314);
    b = md5_II(b, c, d, a, x[k + 13], 21, 0x4e0811a1);
    a = md5_II(a, b, c, d, x[k + 4], 6, 0xf7537e82);
    d = md5_II(d, a, b, c, x[k + 11], 10, 0xbd3af235);
    c = md5_II(c, d, a, b, x[k + 2], 15, 0x2ad7d2bb);
    b = md5_II(b, c, d, a, x[k + 9], 21, 0xeb86d391);

    a = md5_AddUnsigned(a, AA);
    b = md5_AddUnsigned(b, BB);
    c = md5_AddUnsigned(c, CC);
    d = md5_AddUnsigned(d, DD);
  }

  return (md5_WordToHex(a) + md5_WordToHex(b) + md5_WordToHex(c) + md5_WordToHex(d)).toLowerCase();
}

// ============================================================
// Smart Format Detection
// ============================================================

export function detectFormat(text) {
  if (!text || typeof text !== 'string') return [];
  const s = text.trim();
  const hints = [];

  if (s.startsWith('eyJ') && s.split('.').length === 3) {
    hints.push('jwt');
  }

  if (/^[A-Za-z0-9+/=]+$/.test(s) && s.length % 4 === 0 && s.length >= 4) {
    hints.push('base64');
  }

  if (/^[0-9a-fA-F\s]+$/.test(s) && s.replace(/\s/g, '').length % 2 === 0 && s.length >= 2) {
    hints.push('hex');
  }

  if (s.includes('%') && /%[0-9a-fA-F]{2}/.test(s)) {
    hints.push('url');
  }

  if (/&[a-zA-Z0-9#]+;/.test(s)) {
    hints.push('html');
  }

  return hints;
}
