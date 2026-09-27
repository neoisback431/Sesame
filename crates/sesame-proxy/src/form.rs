// SPDX-License-Identifier: Apache-2.0
//! Extraction du formulaire de login et des jetons CSRF depuis la page HTML.

use regex::Regex;
use scraper::{Html, Selector};
use sesame_core::descriptor::{CsrfSource, CsrfToken};

use crate::jar::Jar;
use sesame_core::secret::ExposeSecret;

#[derive(Debug, Default)]
pub struct LoginForm {
    pub action: Option<String>,
    pub method: Option<String>,
    /// Champs `input type=hidden` du formulaire (noms et valeurs non sensibles).
    pub hidden: Vec<(String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum FormError {
    #[error("sélecteur de formulaire invalide")]
    Selector,
    #[error("formulaire de login introuvable")]
    NotFound,
    #[error("jeton CSRF « {0} » introuvable")]
    Csrf(String),
}

pub fn parse_form(html: &str, selector: &str) -> Result<LoginForm, FormError> {
    let doc = Html::parse_document(html);
    let form_sel = Selector::parse(selector).map_err(|_| FormError::Selector)?;
    let form = doc.select(&form_sel).next().ok_or(FormError::NotFound)?;
    let input_sel = Selector::parse("input[type=hidden i][name]").expect("sélecteur statique");
    let hidden = form
        .select(&input_sel)
        .filter_map(|i| {
            let name = i.value().attr("name")?;
            Some((name.to_owned(), i.value().attr("value").unwrap_or("").to_owned()))
        })
        .collect();
    Ok(LoginForm {
        action: form.value().attr("action").map(str::to_owned),
        method: form.value().attr("method").map(str::to_ascii_uppercase),
        hidden,
    })
}

/// Lit un jeton CSRF selon sa source déclarée.
pub fn extract_csrf(token: &CsrfToken, html: &str, jar: &Jar) -> Result<String, FormError> {
    let missing = || FormError::Csrf(token.name.clone());
    match token.source {
        CsrfSource::HiddenInput | CsrfSource::Meta => {
            let doc = Html::parse_document(html);
            let (css, attr) = match token.source {
                CsrfSource::HiddenInput => ("input[name]", "value"),
                _ => ("meta[name]", "content"),
            };
            let sel = Selector::parse(css).expect("sélecteur statique");
            doc.select(&sel)
                .find(|e| e.value().attr("name") == Some(token.name.as_str()))
                .and_then(|e| e.value().attr(attr))
                .map(str::to_owned)
                .ok_or_else(missing)
        }
        CsrfSource::Cookie => jar
            .get(&token.name)
            .map(|v| v.expose_secret().to_owned())
            .ok_or_else(missing),
        CsrfSource::Regex => {
            let pattern = token.pattern.as_deref().ok_or_else(missing)?;
            let re = Regex::new(pattern).map_err(|_| missing())?;
            re.captures(html)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_owned())
                .ok_or_else(missing)
        }
    }
}

#[cfg(test)]
mod tests {
    use sesame_core::descriptor::SendAs;

    use super::*;

    const PAGE: &str = r#"<html><head><meta name="csrf-meta" content="m-123"></head><body>
<form id="search" action="/search"><input type="hidden" name="q" value="x"></form>
<form id="login-form" action="/login" method="post">
  <input type="hidden" name="csrf_token" value="tok-1"><input type="HIDDEN" name="lang" value="fr">
  <input name="username"><input type="password" name="password">
</form><script>var t = "rx-42";</script></body></html>"#;

    fn csrf(source: CsrfSource, name: &str, pattern: Option<&str>) -> CsrfToken {
        CsrfToken {
            source,
            name: name.into(),
            pattern: pattern.map(str::to_owned),
            send_as: SendAs::default(),
        }
    }

    #[test]
    fn parses_selected_form() {
        let f = parse_form(PAGE, "form#login-form").unwrap();
        assert_eq!(f.action.as_deref(), Some("/login"));
        assert_eq!(f.method.as_deref(), Some("POST"));
        assert_eq!(
            f.hidden,
            [
                ("csrf_token".into(), "tok-1".into()),
                ("lang".into(), "fr".into())
            ]
        );
        assert!(matches!(
            parse_form(PAGE, "form#absent"),
            Err(FormError::NotFound)
        ));
        assert!(matches!(parse_form(PAGE, "form[["), Err(FormError::Selector)));
        // Premier formulaire par défaut.
        assert_eq!(
            parse_form(PAGE, "form").unwrap().action.as_deref(),
            Some("/search")
        );
    }

    #[test]
    fn extracts_csrf_tokens() {
        let mut jar = Jar::default();
        jar.apply(["XSRF-TOKEN=c-9"]);
        let get = |t: CsrfToken| extract_csrf(&t, PAGE, &jar);
        assert_eq!(
            get(csrf(CsrfSource::HiddenInput, "csrf_token", None)).unwrap(),
            "tok-1"
        );
        assert_eq!(get(csrf(CsrfSource::Meta, "csrf-meta", None)).unwrap(), "m-123");
        assert_eq!(get(csrf(CsrfSource::Cookie, "XSRF-TOKEN", None)).unwrap(), "c-9");
        assert_eq!(
            get(csrf(CsrfSource::Regex, "t", Some(r#"var t = "([^"]+)""#))).unwrap(),
            "rx-42"
        );
        assert!(get(csrf(CsrfSource::HiddenInput, "absent", None)).is_err());
    }
}
