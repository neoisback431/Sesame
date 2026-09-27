// SPDX-License-Identifier: Apache-2.0
//! Cookie du portail : lecture dans l'en-tête `Cookie`, construction du `Set-Cookie`.

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
