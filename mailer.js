import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const BRAND_NAME = 'OnlyOne Hairboss';
const LOGO_URL = process.env.EMAIL_LOGO_URL || `${FRONTEND_URL}/logo1.svg`;
const EMAIL_FROM = process.env.EMAIL_FROM || `"${BRAND_NAME}" <orders@onlyonehairboss.com>`;
const EMAIL_REPLY_TO = process.env.EMAIL_REPLY_TO || process.env.EMAIL_FROM || undefined;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || process.env.ORDER_ALERT_EMAIL || 'onlyonehairboss@gmail.com';
const EMAIL_PROVIDER = (process.env.EMAIL_PROVIDER || (process.env.RESEND_API_KEY ? 'resend' : 'smtp')).toLowerCase();
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const RESEND_API_URL = process.env.RESEND_API_URL || 'https://api.resend.com/emails';
const EMAIL_TIMEOUT_MS = parseInt(process.env.EMAIL_TIMEOUT_MS || '10000', 10);
const EMAIL_MAX_ATTEMPTS = parseInt(process.env.EMAIL_MAX_ATTEMPTS || '3', 10);
const EMAIL_RETRY_BASE_MS = parseInt(process.env.EMAIL_RETRY_BASE_MS || '3000', 10);

const SMTP_HOST = process.env.SMTP_HOST || process.env.EMAIL_HOST;
const SMTP_PORT = parseInt(process.env.SMTP_PORT || process.env.EMAIL_PORT || '587', 10);
const SMTP_USER = process.env.SMTP_USER || process.env.EMAIL_USER || process.env.EMAIL_USER_NAME;
const SMTP_PASS = process.env.SMTP_PASS || process.env.EMAIL_PASS || process.env.EMAIL_PASSWORD;
const hasSmtpConfig = Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS);
const hasResendConfig = Boolean(RESEND_API_KEY);

let smtpTransporter = null;
if (EMAIL_PROVIDER === 'smtp' && hasSmtpConfig) {
  smtpTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
    connectionTimeout: EMAIL_TIMEOUT_MS,
    greetingTimeout: EMAIL_TIMEOUT_MS,
    socketTimeout: EMAIL_TIMEOUT_MS,
  });
}

const providerStatus = () => {
  if (EMAIL_PROVIDER === 'resend') {
    return hasResendConfig ? 'resend' : 'log-only';
  }
  if (EMAIL_PROVIDER === 'smtp') {
    return hasSmtpConfig ? 'smtp' : 'log-only';
  }
  return 'log-only';
};

console.log(`Mailer: provider=${providerStatus()} timeout=${EMAIL_TIMEOUT_MS}ms maxAttempts=${EMAIL_MAX_ATTEMPTS}`);
if (EMAIL_PROVIDER === 'resend' && !hasResendConfig) {
  console.warn('Mailer: RESEND_API_KEY is missing. Emails will be logged only.');
}
if (EMAIL_PROVIDER === 'smtp') {
  console.warn('Mailer: SMTP mode is enabled. On Render this can time out if the SMTP host/port is blocked or slow.');
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const escapeHtml = (value = '') => String(value)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#039;');

const money = (value) => `NGN ${Number(value || 0).toLocaleString('en-NG')}`;

const stripHtml = (html) => html
  .replace(/<style[\s\S]*?<\/style>/gi, ' ')
  .replace(/<[^>]+>/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();

const normalizeError = (error) => ({
  name: error?.name,
  message: error?.message || String(error),
  code: error?.code,
  command: error?.command,
  status: error?.status,
});

const renderShell = ({ preheader, content }) => `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${BRAND_NAME}</title>
  <style>
    body { margin:0; padding:0; background:#fff1ea; color:#241713; font-family:Arial, Helvetica, sans-serif; }
    .preheader { display:none; max-height:0; overflow:hidden; opacity:0; color:transparent; }
    .wrap { width:100%; background:#fff1ea; padding:32px 12px; }
    .card { max-width:640px; margin:0 auto; background:#fffaf7; border:1px solid rgba(153,85,68,0.18); }
    .hero { padding:34px 28px 28px; text-align:center; background:#1a120e; }
    .logo { max-width:118px; height:auto; margin:0 auto 14px; display:block; }
    .brand { margin:0; color:#fff1ea; font-size:25px; line-height:1.2; letter-spacing:0.5px; font-family:Georgia, 'Times New Roman', serif; font-weight:400; }
    .tag { margin:8px 0 0; color:#d5a08c; font-size:12px; letter-spacing:2px; text-transform:uppercase; }
    .body { padding:34px 30px; font-size:15px; line-height:1.7; color:#3a2a25; }
    h2 { margin:0 0 14px; color:#1a120e; font-size:28px; line-height:1.18; font-family:Georgia, 'Times New Roman', serif; font-weight:400; }
    h3 { margin:28px 0 10px; color:#1a120e; font-size:16px; text-transform:uppercase; letter-spacing:1px; }
    p { margin:0 0 16px; }
    .button { display:inline-block; padding:13px 24px; background:#995544; color:#fff1ea !important; text-decoration:none; font-weight:700; border-radius:3px; }
    .button-wrap { text-align:center; margin:26px 0; }
    .panel { background:#fff1ea; border:1px solid rgba(153,85,68,0.16); padding:18px; margin:18px 0; }
    table { width:100%; border-collapse:collapse; }
    th { color:#7d6259; text-transform:uppercase; letter-spacing:0.8px; font-size:11px; text-align:left; border-bottom:1px solid rgba(153,85,68,0.22); padding:9px 0; }
    td { border-bottom:1px solid rgba(153,85,68,0.12); padding:12px 0; }
    .right { text-align:right; }
    .total td { border-bottom:0; font-weight:700; color:#1a120e; }
    .muted { color:#7d6259; font-size:13px; }
    .footer { padding:22px 30px; text-align:center; color:#8b746c; font-size:12px; background:#fff6f1; border-top:1px solid rgba(153,85,68,0.16); }
    @media (max-width:520px) {
      .wrap { padding:0; }
      .body { padding:28px 20px; }
      .hero { padding:28px 20px 24px; }
      h2 { font-size:24px; }
      .button { display:block; }
    }
  </style>
</head>
<body>
  <span class="preheader">${escapeHtml(preheader)}</span>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <img class="logo" src="${LOGO_URL}" alt="${BRAND_NAME}">
        <h1 class="brand">${BRAND_NAME}</h1>
        <p class="tag">Luxury Hair Studio</p>
      </div>
      <div class="body">${content}</div>
      <div class="footer">
        <p>${new Date().getFullYear()} ${BRAND_NAME}. Luxury hair, handled with care.</p>
        <p class="muted">You received this email because you used ${BRAND_NAME}.</p>
      </div>
    </div>
  </div>
</body>
</html>`;

const buildEmail = ({ title, preheader, intro, ctaLabel, ctaUrl, extraHtml = '', outro = '' }) => {
  const safeCtaUrl = ctaUrl ? escapeHtml(ctaUrl) : '';
  const html = renderShell({
    preheader,
    content: `
      <h2>${escapeHtml(title)}</h2>
      ${intro}
      ${extraHtml}
      ${ctaLabel && safeCtaUrl ? `<div class="button-wrap"><a class="button" href="${safeCtaUrl}">${escapeHtml(ctaLabel)}</a></div>` : ''}
      ${outro}
      ${safeCtaUrl ? `<p class="muted">If the button does not open, copy this link into your browser:<br>${safeCtaUrl}</p>` : ''}
    `,
  });
  return { html, text: stripHtml(html) };
};

const sendWithResend = async ({ to, subject, html, text }) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), EMAIL_TIMEOUT_MS);
  try {
    const response = await fetch(RESEND_API_URL, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: EMAIL_FROM,
        to: [to],
        subject,
        html,
        text,
        ...(EMAIL_REPLY_TO ? { reply_to: EMAIL_REPLY_TO } : {}),
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(body.message || body.error || `Resend HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return body;
  } finally {
    clearTimeout(timeout);
  }
};

const sendWithSmtp = async ({ to, subject, html, text }) => {
  if (!smtpTransporter) {
    throw new Error('SMTP transporter is not configured.');
  }
  return smtpTransporter.sendMail({
    from: EMAIL_FROM,
    to,
    subject,
    html,
    text,
    ...(EMAIL_REPLY_TO ? { replyTo: EMAIL_REPLY_TO } : {}),
  });
};

const sendImmediately = async (email) => {
  const provider = providerStatus();
  if (provider === 'resend') {
    return sendWithResend(email);
  }
  if (provider === 'smtp') {
    return sendWithSmtp(email);
  }

  console.log('\n============================================================');
  console.log(`[EMAIL LOG] TO: ${email.to}`);
  console.log(`[EMAIL LOG] FROM: ${EMAIL_FROM}`);
  console.log(`[EMAIL LOG] SUBJECT: ${email.subject}`);
  console.log('------------------------------------------------------------');
  console.log(email.text.slice(0, 700));
  console.log('============================================================\n');
  return { logged: true };
};

const queue = [];
let processing = false;

const processQueue = async () => {
  if (processing) return;
  processing = true;

  while (queue.length > 0) {
    const job = queue.shift();
    const { email, attempt, event } = job;
    try {
      const result = await sendImmediately(email);
      console.log(`Mailer: ${event} email sent to ${email.to} via ${providerStatus()}.`, result?.id ? `id=${result.id}` : '');
    } catch (error) {
      const normalized = normalizeError(error);
      console.error(`Mailer: ${event} email attempt ${attempt}/${EMAIL_MAX_ATTEMPTS} failed for ${email.to}:`, normalized);
      if (attempt < EMAIL_MAX_ATTEMPTS) {
        const delay = EMAIL_RETRY_BASE_MS * attempt;
        setTimeout(() => {
          queue.push({ ...job, attempt: attempt + 1 });
          processQueue().catch((queueErr) => console.error('Mailer: queue processor error:', queueErr));
        }, delay);
      } else {
        console.error(`Mailer: ${event} email permanently failed for ${email.to}.`, normalized);
      }
    }
  }

  processing = false;
};

export const enqueueEmail = ({ event, to, subject, html, text }) => {
  if (!to || !subject || !html) {
    console.error('Mailer: email enqueue skipped due to missing required fields.', { event, to, subject });
    return Promise.resolve({ queued: false });
  }

  queue.push({
    event: event || 'transactional',
    attempt: 1,
    email: { to, subject, html, text: text || stripHtml(html) },
  });
  setTimeout(() => processQueue().catch((error) => console.error('Mailer: queue processor error:', error)), 0);
  return Promise.resolve({ queued: true });
};

export const getEmailHealth = () => ({
  provider: providerStatus(),
  configuredProvider: EMAIL_PROVIDER,
  resendConfigured: hasResendConfig,
  smtpConfigured: hasSmtpConfig,
  fromConfigured: Boolean(EMAIL_FROM),
  queueDepth: queue.length,
  timeoutMs: EMAIL_TIMEOUT_MS,
  maxAttempts: EMAIL_MAX_ATTEMPTS,
});

export const sendWelcomeEmail = async (email, name) => {
  const firstName = escapeHtml(name || email);
  const { html, text } = buildEmail({
    title: `Welcome, ${firstName}`,
    preheader: 'Your OnlyOne Hairboss account is ready.',
    intro: `
      <p>Your account is active, and your luxury hair experience has officially begun.</p>
      <p>Browse curated wigs, save your details, and track every order from your account dashboard.</p>
    `,
    ctaLabel: 'Explore The Collection',
    ctaUrl: `${FRONTEND_URL}/shop`,
    outro: '<p>Thank you for choosing hair that feels personal, polished, and unmistakably yours.</p>',
  });

  return enqueueEmail({
    event: 'welcome',
    to: email,
    subject: `Welcome to ${BRAND_NAME}`,
    html,
    text,
  });
};

export const sendForgotPasswordEmail = async (email, resetUrl) => {
  const { html, text } = buildEmail({
    title: 'Reset your password',
    preheader: 'Use your secure reset link within one hour.',
    intro: `
      <p>We received a request to reset your ${BRAND_NAME} password.</p>
      <p>This secure link expires in one hour. If you did not request it, you can ignore this email.</p>
    `,
    ctaLabel: 'Reset Password',
    ctaUrl: resetUrl,
  });

  return enqueueEmail({
    event: 'forgot-password',
    to: email,
    subject: `${BRAND_NAME} password reset`,
    html,
    text,
  });
};

export const sendOrderConfirmationEmail = async (email, { name, orderId, total, items, address, city, state }) => {
  const rows = Array.isArray(items) ? items.map((item) => `
    <tr>
      <td>${escapeHtml(item.name || 'OnlyOne Hairboss item')} <span class="muted">x${Number(item.quantity) || 1}</span></td>
      <td class="right">${money((Number(item.price) || 0) * (Number(item.quantity) || 1))}</td>
    </tr>
  `).join('') : '';

  const { html, text } = buildEmail({
    title: 'Order confirmed',
    preheader: `Your order ${orderId} has been received.`,
    intro: `
      <p>Hi ${escapeHtml(name || 'Hairboss')},</p>
      <p>Your payment has been verified and order <strong>#${escapeHtml(orderId)}</strong> is now confirmed.</p>
    `,
    extraHtml: `
      <div class="panel">
        <table>
          <thead><tr><th>Item</th><th class="right">Amount</th></tr></thead>
          <tbody>
            ${rows}
            <tr class="total"><td>Total paid</td><td class="right">${money(total)}</td></tr>
          </tbody>
        </table>
      </div>
      <h3>Delivery Address</h3>
      <p>${escapeHtml(address)}<br>${escapeHtml(city)}, ${escapeHtml(state)}<br>Nigeria</p>
    `,
    ctaLabel: 'Track Your Order',
    ctaUrl: `${FRONTEND_URL}/account`,
  });

  return enqueueEmail({
    event: 'order-confirmed',
    to: email,
    subject: `Order confirmed: #${orderId}`,
    html,
    text,
  });
};

export const sendOrderStatusUpdateEmail = async (email, { name, orderId, oldStatus, newStatus }) => {
  const { html, text } = buildEmail({
    title: 'Order status updated',
    preheader: `Order ${orderId} is now ${newStatus}.`,
    intro: `
      <p>Hi ${escapeHtml(name || 'Hairboss')},</p>
      <p>Your order <strong>#${escapeHtml(orderId)}</strong> moved from <strong>${escapeHtml(oldStatus)}</strong> to <strong>${escapeHtml(newStatus)}</strong>.</p>
      <p>We will keep you updated as your luxury unit moves through fulfillment.</p>
    `,
    ctaLabel: 'View Order',
    ctaUrl: `${FRONTEND_URL}/account`,
  });

  return enqueueEmail({
    event: 'order-status',
    to: email,
    subject: `Order #${orderId} is now ${newStatus}`,
    html,
    text,
  });
};

export const sendAdminOrderNotificationEmail = async ({ name, orderId, total, items, address, city, state }) => {
  const rows = Array.isArray(items) ? items.map((item) => `
    <tr>
      <td>${escapeHtml(item.name || 'OnlyOne Hairboss item')} <span class="muted">x${Number(item.quantity) || 1}</span></td>
      <td class="right">${money((Number(item.price) || 0) * (Number(item.quantity) || 1))}</td>
    </tr>
  `).join('') : '';

  const { html, text } = buildEmail({
    title: 'New order received',
    preheader: `Order ${orderId} was placed by ${name}.`,
    intro: `
      <p>A new paid order <strong>#${escapeHtml(orderId)}</strong> was placed by <strong>${escapeHtml(name || 'Customer')}</strong>.</p>
    `,
    extraHtml: `
      <div class="panel">
        <table>
          <thead><tr><th>Item</th><th class="right">Amount</th></tr></thead>
          <tbody>
            ${rows}
            <tr class="total"><td>Total value</td><td class="right">${money(total)}</td></tr>
          </tbody>
        </table>
      </div>
      <h3>Shipping</h3>
      <p>${escapeHtml(address)}<br>${escapeHtml(city)}, ${escapeHtml(state)}<br>Nigeria</p>
    `,
    ctaLabel: 'Open Admin Orders',
    ctaUrl: `${FRONTEND_URL}/admin/orders`,
  });

  return enqueueEmail({
    event: 'admin-order-alert',
    to: ADMIN_EMAIL,
    subject: `New OnlyOne Hairboss order: #${orderId}`,
    html,
    text,
  });
};
