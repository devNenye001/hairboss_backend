import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const BRAND_NAME = 'OnlyOne Hairboss';
const LOGO_URL = process.env.EMAIL_LOGO_URL || `${FRONTEND_URL}/logo.svg`;
const EMAIL_FROM = process.env.EMAIL_FROM || `"${BRAND_NAME}" <orders@onlyonehairboss.com>`;
const EMAIL_REPLY_TO = process.env.EMAIL_REPLY_TO || undefined;
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
    .hero { padding:40px 20px; text-align:center; background-color:#0c0806; background-image:linear-gradient(rgba(12, 8, 6, 0.2), rgba(12, 8, 6, 0.2)), url('${FRONTEND_URL}/banner.svg'); background-size:cover; background-position:center; }
    .logo { max-width:140px; height:auto; margin:0 auto; display:block; }
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
      .hero { padding:32px 16px; }
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
        <img class="profile-pic" src="${FRONTEND_URL}/hero-image.webp" alt="OnlyOne Hairboss Profile" style="width:70px; height:70px; border-radius:50%; object-fit:cover; border:2px solid #fff1ea; margin:12px auto 0; display:block;">
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

const sendWithResend = async ({ to, subject, html, text, replyTo }) => {
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
        reply_to: replyTo || EMAIL_REPLY_TO || undefined,
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

const sendWithSmtp = async ({ to, subject, html, text, replyTo }) => {
  if (!smtpTransporter) {
    throw new Error('SMTP transporter is not configured.');
  }
  return smtpTransporter.sendMail({
    from: EMAIL_FROM,
    to,
    subject,
    html,
    text,
    replyTo: replyTo || EMAIL_REPLY_TO || undefined,
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

export const enqueueEmail = ({ event, to, subject, html, text, replyTo }) => {
  if (!to || !subject || !html) {
    console.error('Mailer: email enqueue skipped due to missing required fields.', { event, to, subject });
    return Promise.resolve({ queued: false });
  }

  queue.push({
    event: event || 'transactional',
    attempt: 1,
    email: { to, subject, html, text: text || stripHtml(html), replyTo },
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
    title: 'Welcome, Hairboss Queen ✨',
    preheader: 'Your OnlyOne Hairboss account is ready.',
    intro: `
      <p>Hi ${firstName},</p>
      <p>Welcome to OnlyOne Hairboss.</p>
      <p>Your account has been created successfully, and you’re now officially part of our Hairboss Queen community. Explore our collections today and find your next favorite look.</p>
    `,
    ctaLabel: 'Shop Now',
    ctaUrl: `${FRONTEND_URL}/shop`,
  });

  return enqueueEmail({
    event: 'welcome',
    to: email,
    subject: 'Welcome, Hairboss Queen ✨',
    html,
    text,
  });
};

export const sendForgotPasswordEmail = async (email, resetUrl) => {
  const { html, text } = buildEmail({
    title: 'Reset Your Password',
    preheader: 'Reset your OnlyOne Hairboss account password.',
    intro: `
      <p>Hi Hairboss Queen,</p>
      <p>We received a request to reset your password. Click the button below to create a new one:</p>
    `,
    ctaLabel: 'Reset Password',
    ctaUrl: resetUrl,
    outro: '<p>If you didn’t request this change, you can safely ignore this email and your password will remain the same.</p>',
  });

  return enqueueEmail({
    event: 'forgot-password',
    to: email,
    subject: 'Reset Your Password',
    html,
    text,
  });
};

export const sendOrderConfirmationEmail = async (email, { name, orderId, total, items, address, city, state, shippingMethod, shippingFee }) => {
  const rows = Array.isArray(items) ? items.map((item) => `
    <tr>
      <td>${escapeHtml(item.name || 'OnlyOne Hairboss item')} ${item.variant ? `<br><span class="muted" style="font-size:12px;">Variant: ${escapeHtml(item.variant)}</span>` : ''}</td>
      <td>${Number(item.quantity) || 1}</td>
      <td class="right">${money((Number(item.price) || 0) * (Number(item.quantity) || 1))}</td>
    </tr>
  `).join('') : '';

  const shippingFeeVal = Number(shippingFee) || 0;
  const subtotalVal = Number(total) - shippingFeeVal;
  const shippingLabel = shippingMethod === 'international' ? 'DHL (International)' : 'GIG Logistics (Local)';

  const { html, text } = buildEmail({
    title: 'Your Order Has Been Confirmed ✨',
    preheader: `Your order ${orderId} has been confirmed.`,
    intro: `
      <p>Hi Hairboss Queen,</p>
      <p>Thank you for shopping with us! Your order has been received successfully. We’re preparing your items and will keep you updated every step of the way.</p>
      <p><strong>Order Number:</strong> ${escapeHtml(orderId)}<br>
      <strong>Order Date:</strong> ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}</p>
    `,
    extraHtml: `
      <h3 style="margin-top:24px; font-size:14px; color:#1a120e;">🛒 Your Order Details</h3>
      <div class="panel" style="margin-top:8px;">
        <table>
          <thead>
            <tr>
              <th>Item</th>
              <th>Qty</th>
              <th class="right">Price</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
            <tr style="border-top:1px solid rgba(153,85,68,0.22);"><td colspan="3" style="padding:4px 0;"></td></tr>
            <tr class="muted">
              <td>Subtotal</td>
              <td></td>
              <td class="right">${money(subtotalVal)}</td>
            </tr>
            <tr class="muted">
              <td>Shipping (${shippingLabel})</td>
              <td></td>
              <td class="right">${shippingFeeVal > 0 ? money(shippingFeeVal) : 'Free'}</td>
            </tr>
            <tr class="total" style="font-size:16px;">
              <td>Total</td>
              <td></td>
              <td class="right">${money(total)}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <h3 style="margin-top:24px; font-size:14px; color:#1a120e;">📍 Shipping Address</h3>
      <p style="margin-top:6px; line-height:1.6;">
        <strong>${escapeHtml(name || 'Hairboss Queen')}</strong><br>
        ${escapeHtml(address)}<br>
        ${escapeHtml(city)}, ${escapeHtml(state)}<br>
        Nigeria
      </p>
    `,
    ctaLabel: 'View Order Details',
    ctaUrl: `${FRONTEND_URL}/account`,
  });

  return enqueueEmail({
    event: 'order-confirmed',
    to: email,
    subject: 'Your Order Has Been Confirmed ✨',
    html,
    text,
    replyTo: 'onlyonehairboss@gmail.com',
  });
};

export const sendOrderStatusUpdateEmail = async (email, { name, orderId, oldStatus, newStatus }) => {
  const { html, text } = buildEmail({
    title: 'Your Order Has Been Updated ✨',
    preheader: `Your order ${orderId} is now ${newStatus}.`,
    intro: `
      <p>Hi Hairboss Queen,</p>
      <p>There’s an update on your recent order.</p>
      <p><strong>Order Number:</strong> ${escapeHtml(orderId)}<br>
      <strong>Current Status:</strong> ${escapeHtml(newStatus)}</p>
      <p>You can track your package and check your order details anytime using the button below.</p>
    `,
    ctaLabel: 'Track Order',
    ctaUrl: `${FRONTEND_URL}/account`,
  });

  return enqueueEmail({
    event: 'order-status',
    to: email,
    subject: 'Your Order Has Been Updated ✨',
    html,
    text,
  });
};

export const sendAdminOrderNotificationEmail = async ({ name, email, orderId, total, items, address, city, state, shippingMethod, shippingFee }) => {
  const rows = Array.isArray(items) ? items.map((item) => `
    <tr>
      <td>${escapeHtml(item.name || 'OnlyOne Hairboss item')} ${item.variant ? `<span class="muted">(${escapeHtml(item.variant)})</span>` : ''}</td>
      <td class="right">${Number(item.quantity) || 1}</td>
    </tr>
  `).join('') : '';

  const shippingFeeVal = Number(shippingFee) || 0;
  const subtotalVal = Number(total) - shippingFeeVal;
  const shippingLabel = shippingMethod === 'international' ? 'DHL (International)' : 'GIG Logistics (Local)';

  const { html, text } = buildEmail({
    title: `🚨 New Order Alert! Order #${orderId}`,
    preheader: `New order alert from ${name}`,
    intro: `
      <p>Hi Boss,</p>
      <p>You have a new order waiting for fulfillment! A customer has just completed a purchase on OnlyOne Hairboss.</p>
    `,
    extraHtml: `
      <h3 style="margin-top:24px; font-size:14px; color:#1a120e;">📋 Order Summary</h3>
      <p style="margin-top:6px; line-height:1.6;">
        <strong>Order Number:</strong> ${escapeHtml(orderId)}<br>
        <strong>Customer Name:</strong> ${escapeHtml(name || 'Customer')} (${escapeHtml(email || 'No email')})<br>
        <strong>Subtotal:</strong> ${money(subtotalVal)}<br>
        <strong>Shipping (${shippingLabel}):</strong> ${shippingFeeVal > 0 ? money(shippingFeeVal) : 'Free'}<br>
        <strong>Order Total:</strong> ${money(total)}
      </p>
      
      <h3 style="margin-top:24px; font-size:14px; color:#1a120e;">📦 Items Ordered</h3>
      <div class="panel" style="margin-top:8px;">
        <table>
          <thead>
            <tr>
              <th>Item</th>
              <th class="right">Qty</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
      <h3 style="margin-top:24px; font-size:14px; color:#1a120e;">📍 Delivery Address</h3>
      <p style="margin-top:6px; line-height:1.6;">
        ${escapeHtml(address)}<br>
        ${escapeHtml(city)}, ${escapeHtml(state)}<br>
        Nigeria
      </p>
    `,
    ctaLabel: 'Open Admin Orders',
    ctaUrl: `${FRONTEND_URL}/admin/orders`,
  });

  return enqueueEmail({
    event: 'admin-order-alert',
    to: ADMIN_EMAIL,
    subject: `🚨 New Order Alert! Order #${orderId}`,
    html,
    text,
  });
};
