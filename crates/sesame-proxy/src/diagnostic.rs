// SPDX-License-Identifier: Apache-2.0
//! Capture de la dernière réponse de l'appli pendant un rejeu, pour le diagnostic d'un
//! échec dans l'administration (option `SESAME_REPLAY_DEBUG`, ADR 0018).
//!
//! Avant toute sortie du rejeu, les valeurs lues dans le coffre sont masquées sous leurs
//! formes brute, encodée URL, échappée HTML et échappée JSON, et les valeurs des cookies
//! posés par l'appli sont remplacées par `***` : elles ne servent pas à corriger un
//! descripteur.

use reqwest::header::{HeaderMap, SET_COOKIE};
use zeroize::Zeroizing;

/// Taille maximale du corps conservé.
pub const MAX_DIAGNOSTIC_BODY: usize = 64 * 1024;
const MASK: &str = "***";

/// Dernière réponse observée (déjà masquée).
#[derive(Debug, Clone)]
pub struct Capture {
    pub step: &'static str,
    pub method: String,
    pub url: String,
    pub sent_fields: Vec<String>,
    pub status: Option<u16>,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub body_truncated: bool,
}

/// Formes sous lesquelles une valeur du coffre peut réapparaître dans une réponse.
pub struct Masker {
    needles: Vec<Zeroizing<String>>,
}

impl Masker {
    pub fn new<'a>(secrets: impl IntoIterator<Item = &'a str>) -> Self {
        let mut needles: Vec<Zeroizing<String>> = Vec::new();
        for s in secrets.into_iter().filter(|s| !s.is_empty()) {
            let url: String = url::form_urlencoded::byte_serialize(s.as_bytes()).collect();
            let html = s
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#x27;");
            let html_num = html.replace("&#x27;", "&#39;");
            let json = serde_json::Value::String(s.to_owned()).to_string();
            let json = json[1..json.len() - 1].to_owned();
            for n in [s.to_owned(), url, html, html_num, json] {
                if !needles.iter().any(|x| **x == n) {
                    needles.push(Zeroizing::new(n));
                }
            }
        }
        // Les plus longues d'abord : une forme encodée peut contenir la forme brute.
        needles.sort_by_key(|n| std::cmp::Reverse(n.len()));
        Self { needles }
    }

    pub fn mask(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for n in &self.needles {
            if out.contains(n.as_str()) {
                out = out.replace(n.as_str(), MASK);
            }
        }
        out
    }

    /// En-têtes de réponse : secrets masqués, valeurs de `Set-Cookie` remplacées.
    pub fn headers(&self, headers: &HeaderMap) -> Vec<(String, String)> {
        headers
            .iter()
            .map(|(name, value)| {
                let value = String::from_utf8_lossy(value.as_bytes());
                let value = if name == SET_COOKIE {
                    mask_set_cookie(&value)
                } else {
                    value.into_owned()
                };
                (name.as_str().to_owned(), self.mask(&value))
            })
            .collect()
    }

    /// Corps tronqué (sur une frontière de caractère) puis masqué.
    pub fn body(&self, body: &str) -> (String, bool) {
        let truncated = body.len() > MAX_DIAGNOSTIC_BODY;
        let mut end = body.len().min(MAX_DIAGNOSTIC_BODY);
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        (self.mask(&body[..end]), truncated)
    }
}

/// `name=valeur; Path=/` → `name=***; Path=/` (le nom et les attributs aident au diagnostic).
fn mask_set_cookie(value: &str) -> String {
    let (pair, attrs) = value.split_once(';').map_or((value, None), |(p, a)| (p, Some(a)));
    let name = pair.split_once('=').map_or(pair, |(n, _)| n).trim();
    match attrs {
        Some(a) => format!("{name}={MASK};{a}"),
        None => format!("{name}={MASK}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderValue, LOCATION};

    #[test]
    fn masks_every_encoding_of_a_secret() {
        let m = Masker::new(["p&ss w\"<é>", "amartin"]);
        let body = "brut p&ss w\"<é> url p%26ss+w%22%3C%C3%A9%3E html p&amp;ss w&quot;&lt;é&gt; \
                    json p&ss w\\\"<é> user amartin";
        let out = m.mask(body);
        assert!(!out.contains("p&ss") && !out.contains("p%26ss") && !out.contains("p&amp;ss"));
        assert!(!out.contains("amartin"));
        assert_eq!(out.matches(MASK).count(), 5);
    }

    #[test]
    fn set_cookie_values_are_masked_but_names_kept() {
        let m = Masker::new(["pw"]);
        let mut h = HeaderMap::new();
        h.append(
            SET_COOKIE,
            HeaderValue::from_static("sid=abc123; Path=/; HttpOnly"),
        );
        h.append(SET_COOKIE, HeaderValue::from_static("lang=fr"));
        h.append(LOCATION, HeaderValue::from_static("/login?error=pw"));
        let out = m.headers(&h);
        assert!(out.contains(&("set-cookie".into(), "sid=***; Path=/; HttpOnly".into())));
        assert!(out.contains(&("set-cookie".into(), "lang=***".into())));
        assert!(out.contains(&("location".into(), "/login?error=***".into())));
    }

    #[test]
    fn body_is_truncated_on_a_char_boundary() {
        let m = Masker::new([]);
        let long = "é".repeat(MAX_DIAGNOSTIC_BODY);
        let (b, truncated) = m.body(&long);
        assert!(truncated && b.len() <= MAX_DIAGNOSTIC_BODY);
    }
}
