//! Server-sent events fan-out for cert state changes.
//!
//! A single `broadcast::Sender` lives in `AppState`. Anywhere the server
//! mutates cert state (create, renew, delete, status flip in the issuance
//! task or the daily renewal scheduler) it emits a [`CertEvent`]. Each web
//! admin connected to `GET /api/events` subscribes via `Sender::subscribe()`
//! and pushes the events out as SSE frames; the client refetches the
//! affected data on each one.
//!
//! Capacity is intentionally small (256). If a slow client lags far enough
//! behind it gets dropped frames — that's fine for our use case where the
//! response is "refetch this id", which is itself idempotent.

use serde::Serialize;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize)]
pub struct CertEventPayload {
    pub id: String,
}

#[derive(Debug, Clone)]
pub enum CertEvent {
    Changed(CertEventPayload),
    Deleted(CertEventPayload),
}

impl CertEvent {
    pub fn changed(id: impl Into<String>) -> Self {
        Self::Changed(CertEventPayload { id: id.into() })
    }
    pub fn deleted(id: impl Into<String>) -> Self {
        Self::Deleted(CertEventPayload { id: id.into() })
    }

    pub fn event_name(&self) -> &'static str {
        match self {
            Self::Changed(_) => "cert.changed",
            Self::Deleted(_) => "cert.deleted",
        }
    }

    pub fn payload(&self) -> &CertEventPayload {
        match self {
            Self::Changed(p) | Self::Deleted(p) => p,
        }
    }
}

pub type CertEventSender = broadcast::Sender<CertEvent>;

pub fn channel() -> CertEventSender {
    broadcast::channel(256).0
}

/// Best-effort fire-and-forget send. We don't care if there are zero
/// subscribers — that just means no one is watching.
pub fn emit(tx: &CertEventSender, evt: CertEvent) {
    let _ = tx.send(evt);
}
