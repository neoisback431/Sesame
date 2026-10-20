// SPDX-License-Identifier: Apache-2.0
//! Réécriture des URLs internes de l'appli vers son adresse publique.

/// Hôte, schéma et port publics, transmis à l'appli dans les en-têtes `X-Forwarded-*` (ADR 0032).
///
/// Une appli qui connaît son adresse publique génère d'elle-même des URLs correctes : la
/// réécriture a posteriori ne sert plus que de filet. Valeurs tirées du descripteur, jamais
/// de la requête du navigateur : un client ne peut pas choisir l'hôte vu par l'appli.
#[derive(Debug, Clone)]
pub struct Forwarded {
    pub host: String,
    pub proto: String,
    pub port: String,
}

impl Forwarded {
    /// `host` : hôte public avec son port éventuel (`spec.public.host`, ex. `n8n.sesame.example:8443`).
    pub fn new(scheme: &str, host: &str) -> Self {
        let port = host
            .rsplit_once(':')
            .map(|(_, p)| p)
            .filter(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .map_or_else(
                || if scheme == "https" { "443" } else { "80" }.to_owned(),
                str::to_owned,
            );
        Self {
            host: host.to_owned(),
            proto: scheme.to_owned(),
            port,
        }
    }

    /// Pose les trois en-têtes, en remplaçant toute valeur déjà présente.
    pub fn apply(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header("x-forwarded-host", &self.host)
            .header("x-forwarded-proto", &self.proto)
            .header("x-forwarded-port", &self.port)
    }
}

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
    fn forwarded_values_come_from_the_public_host() {
        let f = Forwarded::new("https", "n8n.sesame.example:8443");
        assert_eq!(
            (f.host.as_str(), f.proto.as_str(), f.port.as_str()),
            ("n8n.sesame.example:8443", "https", "8443")
        );
        let f = Forwarded::new("https", "n8n.sesame.example");
        assert_eq!((f.host.as_str(), f.port.as_str()), ("n8n.sesame.example", "443"));
        assert_eq!(Forwarded::new("http", "app.local").port, "80");
    }

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
