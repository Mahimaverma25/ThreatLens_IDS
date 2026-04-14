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
    "Verify your ThreatLens account by opening the link below:",
    verificationUrl,
    "",
    "If you did not request this account, you can ignore this email.",
  ].join("\n");
  const html = `
    <div style="background:#07111f;padding:32px;font-family:Arial,sans-serif;color:#e8f5ff;">
      <div style="max-width:560px;margin:0 auto;border:1px solid rgba(98,214,255,0.2);border-radius:18px;padding:28px;background:#0b1b30;">
        <p style="color:#69ddff;letter-spacing:0.14em;text-transform:uppercase;font-size:12px;margin:0 0 12px;">ThreatLens Account Security</p>
        <h1 style="margin:0 0 12px;font-size:28px;color:#f4fbff;">Verify your email</h1>
        <p style="margin:0 0 18px;line-height:1.7;color:#b7cadd;">Hello ${recipientName}, confirm your email to activate your ThreatLens account and access the platform.</p>
        <a href="${verificationUrl}" style="display:inline-block;padding:14px 20px;border-radius:12px;background:linear-gradient(135deg,#49d0ff,#1c7cf6);color:#02111f;text-decoration:none;font-weight:700;">Verify Email</a>
        <p style="margin:18px 0 0;line-height:1.7;color:#90a9c5;">If the button does not work, open this link:</p>
        <p style="word-break:break-word;color:#69ddff;">${verificationUrl}</p>
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
