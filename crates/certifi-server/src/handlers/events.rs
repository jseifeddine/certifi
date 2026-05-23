//! `GET /api/events` — Server-Sent Events stream of cert state changes.
//!
//! Subscribes to the in-process broadcast channel and forwards each event to
//! the client as an SSE frame with a named event (`cert.changed` /
//! `cert.deleted`) and a JSON payload `{ "id": "..." }`. The browser's
//! built-in `EventSource` reconnects automatically on disconnect, so the
//! client doesn't need any retry logic.

use crate::auth::AuthUser;
use crate::error::AppError;
use crate::rbac::perms;
use crate::AppState;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use std::convert::Infallible;
use std::time::Duration;
use tokio_stream::wrappers::BroadcastStream;

#[utoipa::path(
    get,
    path = "/api/events",
    tag = "events",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Server-Sent Events stream. Named events:\n\
            - `cert.changed` — payload `{\"id\":\"<uuid>\"}` on any cert state \
              transition (create / renew / status flip / delete-already-emitted).\n\
            - `cert.deleted` — payload `{\"id\":\"<uuid>\"}` when a cert is deleted.\n\n\
            The server emits a comment-frame keep-alive every 15s so intermediate \
            proxies don't reap the long-lived response.",
            content_type = "text/event-stream", body = String),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn stream(State(state): State<AppState>, auth: AuthUser) -> Result<Response, AppError> {
    auth.require(perms::CERTIFICATE_LIST)?;
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| async move {
        match res {
            Ok(evt) => {
                let payload = match serde_json::to_string(evt.payload()) {
                    Ok(s) => s,
                    Err(_) => return None,
                };
                let event = Event::default().event(evt.event_name()).data(payload);
                Some(Ok::<_, Infallible>(event))
            }
            // Slow consumer; drop and keep going. Next event will resync them.
            Err(_lagged) => None,
        }
    });

    // 15s keep-alive comment frames keep HAProxy from closing the long-lived
    // response on its `timeout server` budget (default 50s in many setups).
    let sse = Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    );
    Ok(sse.into_response())
}
