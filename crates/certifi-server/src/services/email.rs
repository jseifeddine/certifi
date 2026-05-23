use crate::config::Config;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct EmailNotifier {
    config: Config,
}

impl EmailNotifier {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.smtp_enabled()
    }

    async fn send(&self, to: &str, subject: &str, body: String) -> anyhow::Result<()> {
        let host = match &self.config.smtp_host {
            Some(h) => h.clone(),
            None => return Ok(()),
        };

        let email = Message::builder()
            .from(self.config.smtp_from.parse()?)
            .to(to.parse()?)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;

        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)?
            .port(self.config.smtp_port);

        if let (Some(user), Some(pass)) = (&self.config.smtp_username, &self.config.smtp_password) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }

        let transport = builder.build();
        transport.send(email).await?;
        Ok(())
    }

    pub async fn send_renewal_success(&self, recipients: &[String], cn: &str, expires_at: &str) {
        if !self.is_enabled() {
            return;
        }
        let subject = format!("🦎 Certifi: Certificate renewed — {}", cn);
        let body = format!(
            "Your certificate for {} has been successfully renewed.\n\nExpires: {}\n\n— Certifi",
            cn, expires_at
        );
        for addr in recipients {
            if let Err(e) = self.send(addr, &subject, body.clone()).await {
                tracing::warn!("Email send failed to {}: {}", addr, e);
            }
        }
    }

    pub async fn send_renewal_failure(&self, recipients: &[String], cn: &str, error: &str) {
        if !self.is_enabled() {
            return;
        }
        let subject = format!("🦎 Certifi: Certificate renewal FAILED — {}", cn);
        let body = format!(
            "Auto-renewal of the certificate for {} failed.\n\nError:\n{}\n\nPlease log in to Certifi and renew manually.\n\n— Certifi",
            cn, error
        );
        for addr in recipients {
            if let Err(e) = self.send(addr, &subject, body.clone()).await {
                tracing::warn!("Email send failed to {}: {}", addr, e);
            }
        }
    }

    pub async fn send_expiry_warning(
        &self,
        recipients: &[String],
        cn: &str,
        expires_at: &str,
        days: i64,
    ) {
        if !self.is_enabled() {
            return;
        }
        let subject = format!("🦎 Certifi: Certificate expiring in {} days — {}", days, cn);
        let body = format!(
            "The certificate for {} will expire in {} day(s) on {}.\n\nAuto-renew is disabled for this certificate. Please renew it manually in Certifi.\n\n— Certifi",
            cn, days, expires_at
        );
        for addr in recipients {
            if let Err(e) = self.send(addr, &subject, body.clone()).await {
                tracing::warn!("Email send failed to {}: {}", addr, e);
            }
        }
    }
}
