//! `GET /api/key-algorithms` — the algorithms this server can issue with and
//! the effective default, so clients can build a picker without hardcoding
//! the list. Open to any authenticated caller: it holds nothing sensitive.

use crate::auth::AuthUser;
use crate::error::Result;
use crate::handlers::settings::load_all_settings;
use crate::models::*;
use crate::AppState;
use axum::extract::State;
use axum::Json;

#[utoipa::path(
    get,
    path = "/api/key-algorithms",
    tag = "certificates",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Supported key algorithms, the default a create request \
                                       without `key_algo` gets, and whether `renew` accepts \
                                       `key_algo` (`rekey`).",
            body = KeyAlgorithmsResponse),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list(
    State(state): State<AppState>,
    _auth: AuthUser,
) -> Result<Json<KeyAlgorithmsResponse>> {
    let settings = load_all_settings(&state).await?;
    Ok(Json(build_response(&settings)))
}

fn build_response(settings: &std::collections::HashMap<String, String>) -> KeyAlgorithmsResponse {
    KeyAlgorithmsResponse {
        default: effective_default_key_algo(settings).as_str().to_string(),
        rekey: true,
        algorithms: KeyAlgo::ALL
            .iter()
            .map(|a| KeyAlgorithmInfo {
                id: a.as_str().to_string(),
                label: a.label().to_string(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn lists_every_algorithm_and_the_built_in_default() {
        let r = build_response(&HashMap::new());
        assert_eq!(r.default, "ec-p384");
        assert!(r.rekey);
        let ids: Vec<&str> = r.algorithms.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["ec-p256", "ec-p384", "rsa-2048", "rsa-4096"]);
    }

    #[test]
    fn default_follows_the_global_setting_but_ignores_junk() {
        let mut s = HashMap::new();
        s.insert(S_KEY_ALGO.to_string(), "ec-p256".to_string());
        assert_eq!(build_response(&s).default, "ec-p256");
        s.insert(S_KEY_ALGO.to_string(), "bogus".to_string());
        assert_eq!(build_response(&s).default, "ec-p384");
    }
}
