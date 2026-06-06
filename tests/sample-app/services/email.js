/* Email service for the sample vulnerable app. */

// VULN: hardcoded credentials in source (multiple secret shapes).
const SENDGRID_API_KEY = 'SG.aB3dEfGhIjKlMnOpQrStUv.wXyZ0123456789abcdefghIJKLMNOPqrstuv';
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

function sendWelcome(to) {
  // Pretend to send an email using the hardcoded keys above.
  return { to, sentWith: SENDGRID_API_KEY ? 'sendgrid' : 'none', aws: AWS_ACCESS_KEY_ID };
}

module.exports = { sendWelcome };
