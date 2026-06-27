import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { query } from './db.js';

dotenv.config();

const {
  SMTP_HOST,
  SMTP_PORT,
  SMTP_USER,
  SMTP_PASS,
  EMAIL_FROM,
} = process.env;

const hasSmtpConfig = SMTP_HOST && SMTP_USER && SMTP_PASS;

let transporter = null;

if (hasSmtpConfig) {
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: parseInt(SMTP_PORT || '587', 10),
    secure: parseInt(SMTP_PORT || '587', 10) === 465,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS,
    },
  });
  console.log('Mailer: SMTP transporter initialized.');
} else {
  console.log('Mailer: SMTP config missing. Falling back to log-to-console mode.');
}

const sendMail = async ({ to, subject, html }) => {
  let activeTransporter = transporter;
  let activeFrom = EMAIL_FROM || '"OnlyOne Hairboss" <noreply@onlyonehairboss.com>';

  try {
    const smtpRes = await query("SELECT value FROM site_content WHERE key = $1 LIMIT 1", ['smtp_settings']);
    if (smtpRes && smtpRes.rows.length > 0) {
      const config = smtpRes.rows[0].value;
      if (config && config.host && config.user && config.pass) {
        activeTransporter = nodemailer.createTransport({
          host: config.host,
          port: parseInt(config.port || '587', 10),
          secure: parseInt(config.port || '587', 10) === 465,
          auth: {
            user: config.user,
            pass: config.pass,
          },
        });
        if (config.fromEmail) {
          activeFrom = config.fromEmail;
        }
      }
    }
  } catch (dbErr) {
    // Graceful fallback if database is not fully initialized yet
  }

  if (activeTransporter) {
    try {
      const info = await activeTransporter.sendMail({
        from: activeFrom,
        to,
        subject,
        html,
      });
      console.log(`Mailer: Email sent successfully to ${to}. Message ID: ${info.messageId}`);
      return info;
    } catch (error) {
      console.error(`Mailer: Error sending email to ${to}:`, error);
      throw error;
    }
  } else {
    console.log('\n============================================================');
    console.log(`[EMAIL LOG] TO: ${to}`);
    console.log(`[EMAIL LOG] FROM: ${activeFrom}`);
    console.log(`[EMAIL LOG] SUBJECT: ${subject}`);
    console.log('------------------------------------------------------------');
    console.log(html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500) + '...');
    console.log('============================================================\n');
    return { mock: true };
  }
};

// ── Email Templates ──────────────────────────────────────────────────────────

const BASE_TEMPLATE = (content) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>OnlyOne Hairboss</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f6f5f3;
      margin: 0;
      padding: 0;
      color: #333333;
    }
    .wrapper {
      width: 100%;
      background-color: #f6f5f3;
      padding: 40px 0;
    }
    .container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #ffffff;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 15px rgba(0,0,0,0.05);
      border: 1px solid #eaeaea;
    }
    .header {
      background-color: #111111;
      padding: 30px 20px;
      text-align: center;
      border-bottom: 3px solid #d4af37; /* Luxury Gold border */
    }
    .logo-text {
      color: #ffffff;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 2px;
      margin: 0;
      text-transform: uppercase;
    }
    .logo-sub {
      color: #d4af37;
      font-size: 11px;
      letter-spacing: 3px;
      margin: 5px 0 0 0;
      text-transform: uppercase;
    }
    .content {
      padding: 40px 30px;
      line-height: 1.6;
    }
    .footer {
      background-color: #fcfbf9;
      padding: 20px;
      text-align: center;
      font-size: 12px;
      color: #777777;
      border-top: 1px solid #eeeeee;
    }
    .button {
      display: inline-block;
      padding: 14px 30px;
      background-color: #111111;
      color: #ffffff !important;
      text-decoration: none;
      border-radius: 6px;
      font-weight: 600;
      margin-top: 25px;
      letter-spacing: 1px;
      border: 1px solid #d4af37;
      text-align: center;
    }
    .price-text {
      font-weight: bold;
      color: #111111;
    }
    .details-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    .details-table th {
      text-align: left;
      border-bottom: 2px solid #eeeeee;
      padding: 10px 0;
      font-size: 13px;
      text-transform: uppercase;
      color: #666;
    }
    .details-table td {
      padding: 12px 0;
      border-bottom: 1px solid #f5f5f5;
      font-size: 14px;
    }
    .total-row {
      font-weight: bold;
      font-size: 16px;
      border-top: 2px solid #eeeeee;
    }
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="container">
      <div class="header">
        <h1 class="logo-text">OnlyOne Hairboss</h1>
        <p class="logo-sub">Luxury Hair & Wigs</p>
      </div>
      <div class="content">
        ${content}
      </div>
      <div class="footer">
        <p>&copy; ${new Date().getFullYear()} OnlyOne Hairboss. All rights reserved.</p>
        <p>You received this email because you registered on our platform.</p>
      </div>
    </div>
  </div>
</body>
</html>
`;

export const sendWelcomeEmail = async (email, name) => {
  const html = BASE_TEMPLATE(`
    <h2 style="margin-top:0; color:#111;">Welcome to the Inner Circle, ${name}!</h2>
    <p>We are absolutely thrilled to welcome you to <strong>OnlyOne Hairboss</strong>, your premier destination for the finest quality luxury wigs and hair extensions.</p>
    <p>Your account is now active. You can browse our exclusive collection, track your orders, and manage your shipping details seamlessly.</p>
    <div style="text-align: center;">
      <a href="${process.env.FRONTEND_URL || 'http://localhost:5173'}/shop" class="button">Explore the Collection</a>
    </div>
    <p style="margin-top:30px;">If you have any questions or require personalized recommendation, feel free to hit reply. Our customer care team is always here to assist you.</p>
  `);
  
  return sendMail({
    to: email,
    subject: 'Welcome to OnlyOne Hairboss – Luxury Awaits',
    html,
  });
};

export const sendOrderConfirmationEmail = async (email, { name, orderId, total, items, address, city, state }) => {
  let itemsHtml = '';
  if (items && Array.isArray(items)) {
    itemsHtml = items.map(item => `
      <tr>
        <td>${item.name} <span style="color:#777; font-size:12px;">x${item.quantity}</span></td>
        <td style="text-align: right;" class="price-text">₦${(item.price * item.quantity).toLocaleString()}</td>
      </tr>
    `).join('');
  }

  const html = BASE_TEMPLATE(`
    <h2 style="margin-top:0; color:#27ae60;">Thank You for Your Order!</h2>
    <p>Hi ${name},</p>
    <p>Your payment has been received, and your order <strong>#${orderId}</strong> has been confirmed. We are currently preparing your luxury wig packages for dispatch.</p>
    
    <h3 style="border-bottom:1px solid #eee; padding-bottom:8px; margin-top:30px; color:#111;">Order Details</h3>
    <table class="details-table">
      <thead>
        <tr>
          <th>Item</th>
          <th style="text-align: right;">Price</th>
        </tr>
      </thead>
      <tbody>
        ${itemsHtml}
        <tr class="total-row">
          <td style="padding-top:15px;">Total Paid</td>
          <td style="text-align: right; padding-top:15px;" class="price-text">₦${total.toLocaleString()}</td>
        </tr>
      </tbody>
    </table>

    <h3 style="border-bottom:1px solid #eee; padding-bottom:8px; margin-top:30px; color:#111;">Delivery Address</h3>
    <p style="margin-bottom:0; font-size:14px; color:#555;">
      ${address}<br>
      ${city}, ${state}<br>
      Nigeria
    </p>

    <div style="text-align: center; margin-top:15px;">
      <a href="${process.env.FRONTEND_URL || 'http://localhost:5173'}/account" class="button">Track Your Order</a>
    </div>
  `);

  return sendMail({
    to: email,
    subject: `Order Confirmed: #${orderId} – OnlyOne Hairboss`,
    html,
  });
};

export const sendForgotPasswordEmail = async (email, resetUrl) => {
  const html = BASE_TEMPLATE(`
    <h2 style="margin-top:0; color:#111;">Reset Your Password</h2>
    <p>We received a request to reset the password associated with your account on <strong>OnlyOne Hairboss</strong>.</p>
    <p>Click the button below to choose a new password. This link is secure and will expire in 1 hour.</p>
    <div style="text-align: center;">
      <a href="${resetUrl}" class="button">Reset Password</a>
    </div>
    <p style="margin-top:30px; font-size:13px; color:#666;">If you didn't request this change, you can safely ignore this email. Your password will remain unchanged.</p>
    <p style="font-size:11px; color:#888; word-break: break-all; margin-top:15px;">If the button doesn't work, copy and paste this link in your browser:<br>${resetUrl}</p>
  `);

  return sendMail({
    to: email,
    subject: 'Reset Password Request – OnlyOne Hairboss',
    html,
  });
};
