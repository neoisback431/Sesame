// SPDX-License-Identifier: Apache-2.0
//! Réécriture des URLs internes de l'appli vers son adresse publique.

/// Origine sans barre finale (`http://app:8000`).
pub fn origin(url: &str) -> &str {
    url.trim_end_matches('/')
}

/// Réécrit un en-tête `Location` absolu pointant vers l'origine interne.
pub fn location(value: &str, internal: &str, public: &str) -> Option<String> {
    let rest = value.strip_prefix(internal)?;
    (rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')).then(|| format!("{public}{rest}"))
}

/// Remplace l'origine interne par l'origine publique dans un corps texte.
pub fn body(text: &str, internal: &str, public: &str) -> Option<String> {
    text.contains(internal).then(|| text.replace(internal, public))
}

/// Le type de contenu fait-il partie de ceux à réécrire ?
pub fn content_type_matches(content_type: Option<&str>, allowed: &[String]) -> bool {
    let Some(ct) = content_type else { return false };
    let base = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    allowed.iter().any(|a| a.eq_ignore_ascii_case(&base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_locations() {
        let (i, p) = ("http://app:8000", "https://app.sesame.example");
        assert_eq!(
            location("http://app:8000/x?y=1", i, p).unwrap(),
            "https://app.sesame.example/x?y=1"
        );
        assert_eq!(
            location("http://app:8000", i, p).unwrap(),
            "https://app.sesame.example"
        );
        assert!(location("http://app:80001/x", i, p).is_none());
        assert!(location("/relative", i, p).is_none());
        assert_eq!(origin("http://app:8000/"), "http://app:8000");
    }

    #[test]
    fn rewrites_bodies_by_content_type() {
        let allowed = vec!["text/html".to_string()];
        assert!(content_type_matches(Some("text/html; charset=utf-8"), &allowed));
        assert!(!content_type_matches(Some("image/png"), &allowed));
        assert!(!content_type_matches(None, &allowed));
        assert_eq!(
            body("<a href=\"http://app:8000/a\">", "http://app:8000", "https://p").unwrap(),
            "<a href=\"https://p/a\">"
        );
        assert!(body("rien", "http://app:8000", "https://p").is_none());
    }
}
