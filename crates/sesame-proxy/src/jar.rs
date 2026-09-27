// SPDX-License-Identifier: Apache-2.0
//! Jar de cookies applicatifs, tenu côté serveur. Une appli par nom d'hôte :
//! domaine et chemin des cookies sont ignorés, seul le nom compte.

use std::time::SystemTime;

use cookie::Cookie;
use sesame_core::secret::{AppCookie, ExposeSecret, SecretString};

#[derive(Debug, Default, Clone)]
pub struct Jar {
    cookies: Vec<AppCookie>,
}

impl Jar {
    pub fn from_cookies(cookies: Vec<AppCookie>) -> Self {
        Self { cookies }
    }

    pub fn into_cookies(self) -> Vec<AppCookie> {
        self.cookies
    }

    pub fn contains(&self, name: &str) -> bool {
        self.cookies.iter().any(|c| c.name == name)
    }

    pub fn get(&self, name: &str) -> Option<&SecretString> {
        self.cookies.iter().find(|c| c.name == name).map(|c| &c.value)
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Applique des en-têtes `Set-Cookie`. Renvoie les noms touchés et si le jar a changé.
    pub fn apply<'a>(&mut self, set_cookies: impl IntoIterator<Item = &'a str>) -> (Vec<String>, bool) {
        let mut names = Vec::new();
        let mut changed = false;
        for raw in set_cookies {
            let Ok(c) = Cookie::parse(raw) else { continue };
            let name = c.name().to_owned();
            let expired = c.max_age().is_some_and(|a| a.is_zero() || a.is_negative())
                || c.expires_datetime()
                    .is_some_and(|t| SystemTime::from(t) <= SystemTime::now());
            let pos = self.cookies.iter().position(|x| x.name == name);
            match (expired, pos) {
                (true, Some(i)) => {
                    self.cookies.remove(i);
                    changed = true;
                }
                (true, None) => {}
                (false, Some(i)) => {
                    if self.cookies[i].value.expose_secret() != c.value() {
                        self.cookies[i] = AppCookie::new(name.clone(), c.value());
                        changed = true;
                    }
                }
                (false, None) => {
                    self.cookies.push(AppCookie::new(name.clone(), c.value()));
                    changed = true;
                }
            }
            names.push(name);
        }
        (names, changed)
    }

    /// Valeur de l'en-tête `Cookie` à envoyer à l'appli.
    pub fn header(&self) -> Option<SecretString> {
        if self.cookies.is_empty() {
            return None;
        }
        let value = self
            .cookies
            .iter()
            .map(|c| format!("{}={}", c.name, c.value.expose_secret()))
            .collect::<Vec<_>>()
            .join("; ");
        Some(SecretString::from(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_set_cookie() {
        let mut jar = Jar::default();
        let (names, changed) = jar.apply(["A=1; Path=/; HttpOnly", "B=2", "not a cookie"]);
        assert_eq!(names, ["A", "B"]);
        assert!(changed);
        assert_eq!(jar.header().unwrap().expose_secret(), "A=1; B=2");
        let (_, changed) = jar.apply(["A=1"]);
        assert!(!changed, "valeur identique");
        jar.apply([
            "A=3",
            "B=; Max-Age=0",
            "C=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        ]);
        assert_eq!(jar.header().unwrap().expose_secret(), "A=3");
        assert!(format!("{jar:?}").contains("***") && !format!("{jar:?}").contains("A=3"));
    }
}
