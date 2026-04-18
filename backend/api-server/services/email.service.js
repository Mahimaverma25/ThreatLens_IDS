const config = require("../config/env");

let nodemailer = null;

try {
  nodemailer = require("nodemailer");
} catch (error) {
  nodemailer = null;
}

let transporterPromise = null;

const hasSmtpConfig = () =>
  Boolean(config.smtpHost && config.smtpPort && config.smtpUser && config.smtpPass);

const getTransporter = async () => {
  if (!nodemailer || !hasSmtpConfig()) {
    return null;
  }

  if (!transporterPromise) {
    transporterPromise = Promise.resolve(
      nodemailer.createTransport({
        host: config.smtpHost,
        port: config.smtpPort,
        secure: config.smtpSecure,
        auth: {
          user: config.smtpUser,
          pass: config.smtpPass,
        },
      })
    );
  }

  return transporterPromise;
};

const sendVerificationEmail = async ({ email, username, verificationUrl }) => {
  const transporter = await getTransporter();
  const recipientName = username || email.split("@")[0];
  const subject = "Verify your ThreatLens account";
  const text = [
    `Hello ${recipientName},`,
    "",
    "Welcome to ThreatLens.",
    "",
    "Please verify the email address you used to create your account by opening the link below:",
    verificationUrl,
    "",
    "This verification link will expire soon for security reasons.",
    "",
    "If you did not request this account, you can ignore this email.",
  ].join("\n");
  const html = `
    <div style="background:#07111f;padding:32px 18px;font-family:Arial,sans-serif;color:#e8f5ff;">
      <div style="max-width:560px;margin:0 auto;border:1px solid rgba(98,214,255,0.2);border-radius:22px;overflow:hidden;background:#0b1b30;box-shadow:0 24px 60px rgba(0,0,0,0.35);">
        <div style="padding:32px 32px 20px;background:linear-gradient(135deg,#0f2742,#0b1b30);border-bottom:1px solid rgba(98,214,255,0.12);">
          <p style="color:#69ddff;letter-spacing:0.14em;text-transform:uppercase;font-size:12px;margin:0 0 12px;">ThreatLens Account Security</p>
          <h1 style="margin:0;font-size:30px;line-height:1.15;color:#f4fbff;">Verify your email address</h1>
        </div>
        <div style="padding:28px 32px 32px;">
          <p style="margin:0 0 14px;line-height:1.7;color:#dcecff;">Hello ${recipientName},</p>
          <p style="margin:0 0 18px;line-height:1.7;color:#b7cadd;">Thanks for creating your ThreatLens account. Please confirm that <strong style="color:#f4fbff;">${email}</strong> is your email address so we can activate your access securely.</p>
          <p style="margin:0 0 22px;line-height:1.7;color:#90a9c5;">Click the button below to verify your email and finish setting up your account.</p>
          <a href="${verificationUrl}" style="display:inline-block;padding:14px 22px;border-radius:12px;background:linear-gradient(135deg,#49d0ff,#1c7cf6);color:#02111f;text-decoration:none;font-weight:700;">Verify Email</a>
          <p style="margin:22px 0 0;line-height:1.7;color:#90a9c5;">If the button does not work, copy and paste this link into your browser:</p>
          <p style="margin:10px 0 0;word-break:break-word;color:#69ddff;">${verificationUrl}</p>
          <p style="margin:22px 0 0;line-height:1.7;color:#90a9c5;">If you did not create a ThreatLens account, you can safely ignore this email.</p>
        </div>
      </div>
    </div>
  `;

  if (!transporter) {
    console.log(`[email-preview] Verification link for ${email}: ${verificationUrl}`);
    return {
      delivered: false,
      deliveryMode: "preview",
      previewUrl: verificationUrl,
    };
  }

  await transporter.sendMail({
    from: config.smtpFrom,
    to: email,
    subject,
    text,
    html,
  });

  return {
    delivered: true,
    deliveryMode: "smtp",
  };
};

module.exports = {
  hasSmtpConfig,
  sendVerificationEmail,
};
