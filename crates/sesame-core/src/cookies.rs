// SPDX-License-Identifier: Apache-2.0
//! Cookies propres à Sesame : lecture dans l'en-tête `Cookie`, retrait avant relais,
//! construction du `Set-Cookie` du portail.

/// Recompose un en-tête `Cookie` sans les cookies `names` (cookies propres à Sesame, retirés
/// avant un relais où le navigateur porte la session). `None` s'il ne reste aucun cookie.
pub fn without(header: &str, names: &[&str]) -> Option<String> {
    let kept: Vec<&str> = header
        .split(';')
        .map(str::trim)
        .filter(|c| {
            let name = c.split('=').next().map(str::trim).unwrap_or("");
            !c.is_empty() && !names.contains(&name)
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Valeur du cookie `name` dans un ou plusieurs en-têtes `Cookie`.
pub fn find<'a>(headers: impl IntoIterator<Item = &'a str>, name: &str) -> Option<&'a str> {
    headers
        .into_iter()
        .flat_map(|h| h.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// Attributs du cookie de session portail.
#[derive(Debug, Clone)]
pub struct PortalCookie {
    pub name: String,
    /// Domaine parent, pour que les sous-domaines des applis reçoivent le cookie.
    pub domain: Option<String>,
    pub secure: bool,
}

impl PortalCookie {
    pub fn set(&self, value: &str, max_age_secs: u64) -> String {
        self.build(value, max_age_secs)
    }

    pub fn clear(&self) -> String {
        self.build("", 0)
    }

    fn build(&self, value: &str, max_age: u64) -> String {
        let mut c = format!(
            "{}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax",
            self.name
        );
        if let Some(d) = &self.domain {
            c.push_str("; Domain=");
            c.push_str(d);
        }
        if self.secure {
            c.push_str("; Secure");
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_cookie_across_headers() {
        let headers = ["a=1; sesame_session=tok", "b=2"];
        assert_eq!(find(headers, "sesame_session"), Some("tok"));
        assert_eq!(find(headers, "b"), Some("2"));
        assert_eq!(find(headers, "session"), None);
    }

    #[test]
    fn strips_sesame_cookies_before_relay() {
        let header = "sesame_session=tok; app=1; __sesame_handoff=1; lang=fr";
        let names = ["sesame_session", "__sesame_handoff"];
        assert_eq!(without(header, &names).as_deref(), Some("app=1; lang=fr"));
        assert_eq!(without("sesame_session=tok", &names), None);
    }

    #[test]
    fn builds_secure_cookie() {
        let c = PortalCookie {
            name: "s".into(),
            domain: Some("sesame.example".into()),
            secure: true,
        };
        let set = c.set("v", 60);
        for attr in [
            "s=v",
            "HttpOnly",
            "Secure",
            "SameSite=Lax",
            "Domain=sesame.example",
            "Max-Age=60",
        ] {
            assert!(set.contains(attr), "{set}");
        }
        assert!(c.clear().contains("Max-Age=0"));
    }
}
