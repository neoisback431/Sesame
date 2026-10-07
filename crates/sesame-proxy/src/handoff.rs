// SPDX-License-Identifier: Apache-2.0
//! Mode « remise » (handoff, ADR 0020) : totalement transparent, sans chemin dédié. À la
//! première arrivée sur l'appli, après le rejeu côté serveur, Sesame remet au navigateur
//! l'élément de session (cookie et/ou valeurs de stockage local) et un marqueur, puis le
//! redirige vers l'URL demandée. Les requêtes suivantes (marqueur présent) sont relayées
//! sans nouveau rejeu, le navigateur portant lui-même la session.
//!
//! Exception assumée aux principes 1 et 3 : l'élément remis est visible du navigateur.
//! Le mot de passe applicatif, lui, ne quitte jamais le serveur.

use axum::http::{header, HeaderMap};
use sesame_core::descriptor::Handoff;
use sesame_core::secret::ExposeSecret;

use crate::jar::Jar;

/// Marqueur posé au navigateur par la remise : tant qu'il est présent, les requêtes sont
/// relayées sans nouveau rejeu. Propre à Sesame, il n'est jamais relayé à l'appli.
pub const MARKER: &str = "__sesame_handoff";

/// Le navigateur présente-t-il le marqueur (remise déjà faite) ?
pub fn done(headers: &HeaderMap) -> bool {
    let values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok());
    sesame_core::cookies::find(values, MARKER).is_some()
}

/// Le navigateur porte-t-il encore tous les cookies remis (`set_cookies`) ? Faux quand l'appli
/// les a effacés elle-même (déconnexion faite dans l'appli) alors que le marqueur subsiste :
/// la remise est à refaire. Sans cookie remis (jeton en stockage local seul), rien à vérifier.
pub fn cookies_present(headers: &HeaderMap, handoff: &Handoff) -> bool {
    handoff.set_cookies.iter().all(|name| {
        let values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok());
        sesame_core::cookies::find(values, name).is_some_and(|v| !v.is_empty())
    })
}

/// `Set-Cookie` de la remise : cookies capturés déclarés dans `set_cookies` (visibles du
/// navigateur : c'est l'exception de l'ADR 0020), puis le marqueur. Durée : `ttl_secs`.
pub fn set_cookie_headers(handoff: &Handoff, jar: &Jar, ttl_secs: u64) -> Vec<String> {
    let mut out: Vec<String> = handoff
        .set_cookies
        .iter()
        .filter_map(|name| {
            jar.get(name).map(|value| {
                format!(
                    "{name}={}; Path=/; Secure; SameSite=Lax; Max-Age={ttl_secs}",
                    value.expose_secret()
                )
            })
        })
        .collect();
    out.push(format!(
        "{MARKER}=1; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={ttl_secs}"
    ));
    out
}

/// Valeurs à écrire dans le stockage local, extraites du corps JSON de la réponse au login.
/// Renvoie une erreur (code court) si le corps manque ou si une clé est introuvable.
pub fn local_storage_values(
    handoff: &Handoff,
    login_body: Option<&str>,
) -> Result<Vec<(String, String)>, &'static str> {
    if handoff.local_storage.is_empty() {
        return Ok(Vec::new());
    }
    let body = login_body.ok_or("handoff_login_body_missing")?;
    let json: serde_json::Value = serde_json::from_str(body).map_err(|_| "handoff_login_body_not_json")?;
    let mut out = Vec::with_capacity(handoff.local_storage.len());
    for item in &handoff.local_storage {
        let value = item
            .from_response
            .split('.')
            .try_fold(&json, |v, key| v.get(key))
            .ok_or("handoff_value_not_found")?;
        let text = match value {
            serde_json::Value::String(s) if !s.is_empty() => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => return Err("handoff_value_not_found"),
        };
        out.push((item.key.clone(), text));
    }
    Ok(out)
}

/// `<` échappé pour qu'aucune valeur ne referme le bloc `<script>` (pas d'exécution injectée).
fn json_for_script(items: &[(String, String)]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = items
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::Value::Object(map).to_string().replace('<', "\\u003c")
}

/// Page de remise : écrit les valeurs dans `localStorage` (bloc JSON lu par `textContent`,
/// jamais interprété comme du code) puis remplace l'URL par `return_path`, l'URL demandée.
/// Sert quand des valeurs de stockage local sont à poser ; les cookies éventuels voyagent en
/// `Set-Cookie` sur la même réponse.
pub fn page(items: &[(String, String)], return_path: &str, portal_url: &str) -> String {
    let data = json_for_script(items);
    let body = format!(
        "<h1>Connexion en cours…</h1><p class=\"muted\">Redirection automatique.</p>\
         <script type=\"application/json\" id=\"sesame-handoff\">{data}</script>\
         <script>(function(){{\
         try{{var d=JSON.parse(document.getElementById('sesame-handoff').textContent);\
         for(var k in d){{localStorage.setItem(k,d[k]);}}}}catch(e){{}}\
         location.replace({start});}})();</script>",
        start = serde_json::Value::String(return_path.to_owned()),
    );
    sesame_core::html::page("Connexion", &body, portal_url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sesame_core::descriptor::HandoffItem;

    fn handoff(pairs: &[(&str, &str)]) -> Handoff {
        Handoff {
            set_cookies: Vec::new(),
            local_storage: pairs
                .iter()
                .map(|(key, from)| HandoffItem {
                    key: (*key).into(),
                    from_response: (*from).into(),
                })
                .collect(),
            redirect_status: 303,
        }
    }

    #[test]
    fn extracts_values_by_pointed_path() {
        let h = handoff(&[("refreshToken", "refreshToken"), ("id", "user.id")]);
        let body = r#"{"accessToken":"a","refreshToken":"r-42","user":{"id":7,"name":"k"}}"#;
        let v = local_storage_values(&h, Some(body)).unwrap();
        assert_eq!(
            v,
            vec![("refreshToken".into(), "r-42".into()), ("id".into(), "7".into())]
        );
    }

    #[test]
    fn missing_body_or_key_is_an_error() {
        let h = handoff(&[("t", "token")]);
        assert_eq!(local_storage_values(&h, None), Err("handoff_login_body_missing"));
        assert_eq!(
            local_storage_values(&h, Some("{}")),
            Err("handoff_value_not_found")
        );
        assert_eq!(
            local_storage_values(&h, Some("x")),
            Err("handoff_login_body_not_json")
        );
    }

    #[test]
    fn set_cookie_headers_hand_over_declared_cookies_then_the_marker() {
        let mut h = handoff(&[]);
        h.set_cookies = vec!["SID".into(), "absent".into()];
        let jar = Jar::from_cookies(vec![
            sesame_core::secret::AppCookie::new("SID", "v-1"),
            sesame_core::secret::AppCookie::new("OTHER", "x"),
        ]);
        let headers = set_cookie_headers(&h, &jar, 60);
        assert_eq!(
            headers.len(),
            2,
            "cookie absent ignoré, OTHER non déclaré : {headers:?}"
        );
        assert_eq!(headers[0], "SID=v-1; Path=/; Secure; SameSite=Lax; Max-Age=60");
        assert!(headers[1].starts_with("__sesame_handoff=1;") && headers[1].contains("HttpOnly"));
    }

    #[test]
    fn marker_is_detected_among_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "a=1; __sesame_handoff=1".parse().unwrap());
        assert!(done(&headers));
        headers.insert(header::COOKIE, "a=1".parse().unwrap());
        assert!(!done(&headers));
    }

    #[test]
    fn page_embeds_values_without_breaking_out_of_the_script() {
        let items = vec![("k".to_string(), "</script><b>x".to_string())];
        let html = page(&items, "/app", "https://sesame.test/");
        assert!(!html.contains("</script><b>x"), "valeur non échappée");
        assert!(html.contains("\\u003c/script>"));
        assert!(html.contains("location.replace(\"/app\")"));
        assert!(html.contains("localStorage.setItem"));
    }
}
