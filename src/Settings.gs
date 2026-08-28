var API_KEY_PROPERTY = 'SPAMHAUS_API_KEY';

/**
 * @return {string} The saved API key, or '' if none is stored.
 */
function getApiKey_() {
  return PropertiesService.getUserProperties().getProperty(API_KEY_PROPERTY) || '';
}

/**
 * @param {string} key API key to store. Blank clears the stored value.
 */
function setApiKey_(key) {
  var properties = PropertiesService.getUserProperties();
  var trimmed = String(key || '').trim();
  if (trimmed) {
    properties.setProperty(API_KEY_PROPERTY, trimmed);
  } else {
    properties.deleteProperty(API_KEY_PROPERTY);
  }
}

/**
 * Shows enough of the key to confirm which one is saved, without printing it.
 *
 * @param {string} key API key.
 * @return {string} Masked representation.
 */
function maskApiKey_(key) {
  if (!key) {
    return 'not set';
  }
  if (key.length <= 8) {
    return '••••';
  }
  return key.slice(0, 4) + '••••' + key.slice(-4);
}

/**
 * Handler for the "Save" button on the settings card.
 *
 * @param {!Object} e Add-on event object.
 * @return {!ActionResponse} Notification plus a refreshed settings card.
 */
function onSaveApiKey(e) {
  var input = (e.formInput && e.formInput.apiKey) || '';
  var trimmed = String(input).trim();

  if (!trimmed) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText('Enter a key first.'))
        .build();
  }

  setApiKey_(trimmed);
  CacheService.getUserCache().remove(THREAT_TYPE_CACHE_KEY);

  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('API key saved.'))
      .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard_()))
      .build();
}

/**
 * Handler for the "Clear key" button on the settings card.
 *
 * @return {!ActionResponse} Notification plus a refreshed settings card.
 */
function onClearApiKey() {
  setApiKey_('');
  CacheService.getUserCache().remove(THREAT_TYPE_CACHE_KEY);

  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText('API key cleared.'))
      .setNavigation(CardService.newNavigation().updateCard(buildSettingsCard_()))
      .build();
}

/**
 * Handler for the "Test connection" button: verifies the key against a cheap
 * authenticated endpoint so the user finds out now rather than mid-report.
 *
 * @return {!ActionResponse} Notification describing the outcome.
 */
function onTestApiKey() {
  var message;
  try {
    CacheService.getUserCache().remove(THREAT_TYPE_CACHE_KEY);
    spamhausRequest_('lookup/threats-types', 'get');
    message = 'Key works — Spamhaus accepted it.';
  } catch (err) {
    message = String(err.message || err);
  }
  return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText(message))
      .build();
}