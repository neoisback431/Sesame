// SPDX-License-Identifier: Apache-2.0
//! Mode « remise » (handoff, ADR 0020) : après le rejeu côté serveur, Sesame remet au
//! navigateur l'élément de session (cookie et/ou valeurs de stockage local) puis le
//! redirige vers la page d'arrivée. L'appli est ensuite jointe directement.
//!
//! Exception assumée aux principes 1 et 3 : l'élément remis est visible du navigateur.
//! Le mot de passe applicatif, lui, ne quitte jamais le serveur.

use sesame_core::descriptor::Handoff;

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
/// jamais interprété comme du code) puis remplace l'URL par `start_path`. Sert quand des
/// valeurs de stockage local sont à poser ; les cookies éventuels voyagent en `Set-Cookie`.
pub fn page(items: &[(String, String)], start_path: &str, portal_url: &str) -> String {
    let data = json_for_script(items);
    let body = format!(
        "<h1>Connexion en cours…</h1><p class=\"muted\">Redirection automatique.</p>\
         <script type=\"application/json\" id=\"sesame-handoff\">{data}</script>\
         <script>(function(){{\
         try{{var d=JSON.parse(document.getElementById('sesame-handoff').textContent);\
         for(var k in d){{localStorage.setItem(k,d[k]);}}}}catch(e){{}}\
         location.replace({start});}})();</script>",
        start = serde_json::Value::String(start_path.to_owned()),
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
    fn page_embeds_values_without_breaking_out_of_the_script() {
        let items = vec![("k".to_string(), "</script><b>x".to_string())];
        let html = page(&items, "/app", "https://sesame.test/");
        assert!(!html.contains("</script><b>x"), "valeur non échappée");
        assert!(html.contains("\\u003c/script>"));
        assert!(html.contains("location.replace(\"/app\")"));
        assert!(html.contains("localStorage.setItem"));
    }
}
