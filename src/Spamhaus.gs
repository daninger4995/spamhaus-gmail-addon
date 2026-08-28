var SPAMHAUS_API_BASE = 'https://submit.spamhaus.org/portal/api/v1/';

/** The portal rejects a `source.object` larger than 150KB. */
var MAX_SOURCE_BYTES = 150 * 1024;

/** Cache key + TTL for the threat-type lookup. */
var THREAT_TYPE_CACHE_KEY = 'spamhaus_email_threat_types_v1';
var THREAT_TYPE_CACHE_TTL = 6 * 60 * 60; // 6 hours, in seconds.

/**
 * Used when the lookup endpoint is unreachable so the add-on still works.
 * These codes are the ones the portal's own email form offers.
 */
var FALLBACK_THREAT_TYPES = [
  { code: 'spam', desc: 'Spam / unsolicited bulk email' },
  { code: 'phish', desc: 'Phishing' },
  { code: 'malware', desc: 'Malware' },
  { code: 'scam', desc: 'Scam / fraud' }
];

/**
 * Performs an authenticated request against the submission API.
 *
 * @param {string} path Path relative to SPAMHAUS_API_BASE.
 * @param {string} method HTTP method.
 * @param {Object=} payload Optional JSON body.
 * @return {Object} Parsed response body.
 */
function spamhausRequest_(path, method, payload) {
  var apiKey = getApiKey_();
  if (!apiKey) {
    throw new Error('No Spamhaus API key saved yet. Open Settings and paste your key.');
  }

  var options = {
    method: method,
    contentType: 'application/json',
    headers: { Authorization: 'Bearer ' + apiKey },
    muteHttpExceptions: true
  };
  if (payload) {
    options.payload = JSON.stringify(payload);
  }

  var response = UrlFetchApp.fetch(SPAMHAUS_API_BASE + path, options);
  var status = response.getResponseCode();
  var text = response.getContentText();

  var body = null;
  try {
    body = JSON.parse(text);
  } catch (err) {
    // Leave body null; describeApiError_ falls back to the raw text.
  }

  if (status < 200 || status >= 300) {
    throw new Error(describeApiError_(status, body, text));
  }
  return body;
}

/**
 * Turns an API failure into something worth showing in the sidebar.
 *
 * @param {number} status HTTP status code.
 * @param {Object} body Parsed response body, or null.
 * @param {string} text Raw response text.
 * @return {string} Human-readable message.
 */
function describeApiError_(status, body, text) {
  var detail = '';
  if (body) {
    detail = body.message || body.error || body.detail || '';
    if (!detail && body.errors) {
      detail = JSON.stringify(body.errors);
    }
  }
  if (!detail) {
    detail = String(text || '').slice(0, 300);
  }

  switch (status) {
    case 401:
    case 403:
      return 'Spamhaus rejected the API key (HTTP ' + status + '). Create a fresh key at ' +
          'auth.spamhaus.org/account and re-save it in Settings. ' + detail;
    case 413:
      return 'Spamhaus refused the message as too large (HTTP 413). ' + detail;
    case 429:
      return 'Rate limited by Spamhaus (HTTP 429). Wait a moment and try again. ' + detail;
    default:
      return 'Spamhaus API error (HTTP ' + status + '). ' + detail;
  }
}

/**
 * Fetches the threat types valid for email submissions, cached per user.
 *
 * @return {!Array<{code: string, desc: string}>} Selectable threat types.
 */
function fetchEmailThreatTypes_() {
  var cache = CacheService.getUserCache();
  var cached = cache.get(THREAT_TYPE_CACHE_KEY);
  if (cached) {
    try {
      return JSON.parse(cached);
    } catch (err) {
      // Fall through and re-fetch.
    }
  }

  var types;
  try {
    var body = spamhausRequest_('lookup/threats-types', 'get');
    var rows = (body && (body.results || body.data || body)) || [];
    types = rows
        .filter(function (row) {
          // `type` is '*' for codes valid on any submission, or the specific kind.
          return row && row.code && (!row.type || row.type === '*' || row.type === 'email');
        })
        .map(function (row) {
          return { code: String(row.code), desc: String(row.desc || row.code) };
        });
  } catch (err) {
    types = [];
  }

  if (!types.length) {
    types = FALLBACK_THREAT_TYPES;
  }
  cache.put(THREAT_TYPE_CACHE_KEY, JSON.stringify(types), THREAT_TYPE_CACHE_TTL);
  return types;
}

/**
 * Finds the largest cut point at or below `limit` that lands on a UTF-8
 * character boundary.
 *
 * Cutting mid-character would decode to a replacement character, which
 * re-encodes to three bytes and can push the result back over the limit.
 *
 * @param {!Array<number>} bytes UTF-8 bytes (signed, as Apps Script returns).
 * @param {number} limit Maximum number of bytes to keep.
 * @return {number} Safe cut length.
 */
function utf8BoundaryBefore_(bytes, limit) {
  var end = Math.min(limit, bytes.length);
  // Continuation bytes match 10xxxxxx; walk back until the next byte starts a
  // character, so everything before `end` is a whole character.
  while (end > 0 && end < bytes.length && (bytes[end] & 0xC0) === 0x80) {
    end--;
  }
  return end;
}

/**
 * Trims raw message source to the portal's size ceiling.
 *
 * @param {string} raw RFC 822 source.
 * @return {{raw: string, truncated: boolean, originalBytes: number}} Clamped source.
 */
function clampSource_(raw) {
  var bytes = Utilities.newBlob(raw).getBytes();
  if (bytes.length <= MAX_SOURCE_BYTES) {
    return { raw: raw, truncated: false, originalBytes: bytes.length };
  }
  var notice = '\r\n\r\n[truncated by Spamhaus Submitter to fit the 150KB API limit]';
  var budget = MAX_SOURCE_BYTES - Utilities.newBlob(notice).getBytes().length;
  var cut = utf8BoundaryBefore_(bytes, budget);
  var head = Utilities.newBlob(bytes.slice(0, cut)).getDataAsString();
  return { raw: head + notice, truncated: true, originalBytes: bytes.length };
}

/**
 * Submits one raw email to Spamhaus.
 *
 * @param {string} rawEmail RFC 822 source of the message.
 * @param {string} threatType Threat type code.
 * @param {string} reason Free-text justification.
 * @return {{response: Object, truncated: boolean, originalBytes: number}} Result.
 */
function submitEmailToSpamhaus_(rawEmail, threatType, reason) {
  var clamped = clampSource_(rawEmail);
  var response = spamhausRequest_('submissions/add/email', 'post', {
    threat_type: threatType,
    reason: reason,
    source: { object: clamped.raw }
  });
  return {
    response: response,
    truncated: clamped.truncated,
    originalBytes: clamped.originalBytes
  };
}