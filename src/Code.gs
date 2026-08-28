var DEFAULT_REASON = 'Unsolicited/malicious message received in my mailbox.';

/**
 * Contextual trigger: runs when a message is opened.
 *
 * @param {!Object} e Add-on event object.
 * @return {!Array<!Card>} The submission card.
 */
function onGmailMessage(e) {
  if (!getApiKey_()) {
    return [buildSettingsCard_('Add your Spamhaus API key to start submitting.')];
  }

  try {
    var message = getCurrentMessage_(e);
    return [buildSubmitCard_(message)];
  } catch (err) {
    return [buildErrorCard_('Could not read this message', String(err.message || err))];
  }
}

/**
 * Homepage trigger: runs when the add-on is opened outside a message.
 *
 * @return {!Array<!Card>} Settings, or a prompt to open a message.
 */
function onHomepage() {
  if (!getApiKey_()) {
    return [buildSettingsCard_('Add your Spamhaus API key to get started.')];
  }
  return [buildInfoCard_(
      'Spamhaus Submitter',
      'Open a spam message in Gmail, then reopen this add-on to submit it.')];
}

/**
 * Universal action: the Settings entry in the add-on menu.
 *
 * @return {!UniversalActionResponse} Navigation to the settings card.
 */
function onSettings() {
  return CardService.newUniversalActionResponseBuilder()
      .displayAddOnCards([buildSettingsCard_()])
      .build();
}

/**
 * Resolves the currently open Gmail message.
 *
 * The add-on holds only a temporary, message-scoped token, so it has to be
 * activated on GmailApp before the message can be read.
 *
 * @param {!Object} e Add-on event object.
 * @return {!GmailMessage} The open message.
 */
function getCurrentMessage_(e) {
  if (!e || !e.gmail || !e.gmail.messageId) {
    throw new Error('No Gmail message is open.');
  }
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

/**
 * Builds the main card: what will be sent, how to classify it, and the button.
 *
 * @param {!GmailMessage} message The open message.
 * @return {!Card} The submission card.
 */
function buildSubmitCard_(message) {
  var section = CardService.newCardSection();

  section.addWidget(CardService.newDecoratedText()
      .setTopLabel('From')
      .setText(escapeForCard_(message.getFrom()))
      .setWrapText(true));
  section.addWidget(CardService.newDecoratedText()
      .setTopLabel('Subject')
      .setText(escapeForCard_(message.getSubject() || '(no subject)'))
      .setWrapText(true));

  var threatTypes = fetchEmailThreatTypes_();
  var dropdown = CardService.newSelectionInput()
      .setType(CardService.SelectionInputType.DROPDOWN)
      .setTitle('Threat type')
      .setFieldName('threatType');
  threatTypes.forEach(function (type, index) {
    var isDefault = type.code === 'spam' || (index === 0 && !hasCode_(threatTypes, 'spam'));
    dropdown.addItem(type.desc, type.code, isDefault);
  });
  section.addWidget(dropdown);

  section.addWidget(CardService.newTextInput()
      .setFieldName('reason')
      .setTitle('Reason')
      .setMultiline(true)
      .setValue(DEFAULT_REASON));

  section.addWidget(CardService.newTextButton()
      .setText('Submit to Spamhaus')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setOnClickAction(CardService.newAction()
          .setFunctionName('onSubmitMessage')));

  section.addWidget(CardService.newTextParagraph()
      .setText('<font color="#777777">The full raw message source is sent, ' +
          'including headers.</font>'));

  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Report this message'))
      .addSection(section)
      .build();
}

/**
 * @param {!Array<{code: string}>} types Threat types.
 * @param {string} code Code to look for.
 * @return {boolean} Whether the code is present.
 */
function hasCode_(types, code) {
  return types.some(function (type) {
    return type.code === code;
  });
}

/**
 * Handler for the "Submit to Spamhaus" button.
 *
 * @param {!Object} e Add-on event object.
 * @return {!ActionResponse} Navigation to a result card.
 */
function onSubmitMessage(e) {
  var form = e.formInput || {};
  var threatType = form.threatType;
  var reason = String(form.reason || '').trim() || DEFAULT_REASON;

  if (!threatType) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText('Pick a threat type.'))
        .build();
  }

  try {
    var message = getCurrentMessage_(e);
    var result = submitEmailToSpamhaus_(message.getRawContent(), threatType, reason);
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification().setText('Submitted to Spamhaus.'))
        .setNavigation(CardService.newNavigation().pushCard(buildResultCard_(result)))
        .build();
  } catch (err) {
    return CardService.newActionResponseBuilder()
        .setNotification(CardService.newNotification()
            .setText(truncateForNotification_(String(err.message || err))))
        .setNavigation(CardService.newNavigation()
            .pushCard(buildErrorCard_('Submission failed', String(err.message || err))))
        .build();
  }
}

/**
 * Builds the post-submission confirmation card.
 *
 * @param {{response: Object, truncated: boolean, originalBytes: number}} result
 *     Outcome from submitEmailToSpamhaus_.
 * @return {!Card} The result card.
 */
function buildResultCard_(result) {
  var section = CardService.newCardSection();
  section.addWidget(CardService.newDecoratedText()
      .setText('Submitted to Spamhaus')
      .setBottomLabel('Thanks — the message was accepted.')
      .setWrapText(true));

  var reference = extractSubmissionReference_(result.response);
  if (reference) {
    section.addWidget(CardService.newDecoratedText()
        .setTopLabel('Reference')
        .setText(escapeForCard_(reference))
        .setWrapText(true));
  }

  if (result.truncated) {
    section.addWidget(CardService.newTextParagraph().setText(
        'Note: the message was ' + Math.round(result.originalBytes / 1024) +
        'KB, so it was truncated to the 150KB the API accepts. Headers and the ' +
        'start of the body were preserved.'));
  }

  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Done'))
      .addSection(section)
      .build();
}

/**
 * Pulls a submission id out of the API response, whatever it calls the field.
 *
 * @param {Object} response Parsed API response.
 * @return {string} Reference, or '' when the response carries none.
 */
function extractSubmissionReference_(response) {
  if (!response || typeof response !== 'object') {
    return '';
  }
  var candidates = [response.id, response.submission_id, response.reference, response.uuid];
  if (response.data && typeof response.data === 'object') {
    candidates = candidates.concat(
        [response.data.id, response.data.submission_id, response.data.reference]);
  }
  for (var i = 0; i < candidates.length; i++) {
    if (candidates[i]) {
      return String(candidates[i]);
    }
  }
  return '';
}

/**
 * Builds the settings card.
 *
 * @param {string=} intro Optional message shown above the field.
 * @return {!Card} The settings card.
 */
function buildSettingsCard_(intro) {
  var section = CardService.newCardSection();

  if (intro) {
    section.addWidget(CardService.newTextParagraph().setText(escapeForCard_(intro)));
  }

  section.addWidget(CardService.newDecoratedText()
      .setTopLabel('Current key')
      .setText(maskApiKey_(getApiKey_())));

  section.addWidget(CardService.newTextInput()
      .setFieldName('apiKey')
      .setTitle('Spamhaus API key')
      .setHint('Create one at auth.spamhaus.org/account under "API Key Creation".'));

  var buttons = CardService.newButtonSet()
      .addButton(CardService.newTextButton()
          .setText('Save')
          .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
          .setOnClickAction(CardService.newAction().setFunctionName('onSaveApiKey')))
      .addButton(CardService.newTextButton()
          .setText('Test')
          .setOnClickAction(CardService.newAction().setFunctionName('onTestApiKey')))
      .addButton(CardService.newTextButton()
          .setText('Clear')
          .setOnClickAction(CardService.newAction().setFunctionName('onClearApiKey')));
  section.addWidget(buttons);

  section.addWidget(CardService.newTextParagraph().setText(
      '<font color="#777777">The key is stored in your own Apps Script user ' +
      'properties and is not shared with anyone else.</font>'));

  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Spamhaus settings'))
      .addSection(section)
      .build();
}

/**
 * @param {string} title Card title.
 * @param {string} body Body text.
 * @return {!Card} A plain informational card.
 */
function buildInfoCard_(title, body) {
  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle(title))
      .addSection(CardService.newCardSection()
          .addWidget(CardService.newTextParagraph().setText(escapeForCard_(body))))
      .build();
}

/**
 * @param {string} title Card title.
 * @param {string} detail Error detail.
 * @return {!Card} An error card with a route back to settings.
 */
function buildErrorCard_(title, detail) {
  var section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(escapeForCard_(detail)))
      .addWidget(CardService.newTextButton()
          .setText('Open settings')
          .setOnClickAction(CardService.newAction().setFunctionName('onOpenSettingsCard')));

  return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle(title))
      .addSection(section)
      .build();
}

/**
 * handler for the "Open settings" button on the error card.
 *
 * @return {!ActionResponse} Navigation to the settings card.
 */
function onOpenSettingsCard() {
  return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().pushCard(buildSettingsCard_()))
      .build();
}

/**
 * Escapes text that card widgets would otherwise render as HTML.
 *
 * @param {string} text Untrusted text, e.g. a sender or subject.
 * @return {string} Escaped text.
 */
function escapeForCard_(text) {
  return String(text == null ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
}

/**
 * @param {string} text Message text.
 * @return {string} Text short enough for a notification toast.
 */
function truncateForNotification_(text) {
  return text.length > 180 ? text.slice(0, 177) + '...' : text;
}