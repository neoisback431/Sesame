// SPDX-License-Identifier: Apache-2.0
//! Évaluation des conditions des descripteurs (`success`, `failure`, `expiry`).

use regex::Regex;
use sesame_core::descriptor::{Matcher, MatcherSet};

/// Vue d'une réponse HTTP, suffisante pour évaluer une condition.
pub struct ResponseView<'a> {
    pub status: u16,
    pub location: Option<&'a str>,
    pub set_cookie_names: &'a [String],
    /// `None` si le corps n'a pas été lu (aucune condition ne l'exige).
    pub body: Option<&'a str>,
}

fn regex_matches(pattern: &str, text: &str) -> bool {
    // Les regex sont validées au chargement du descripteur.
    Regex::new(pattern).is_ok_and(|r| r.is_match(text))
}

pub fn matches(m: &Matcher, r: &ResponseView<'_>) -> bool {
    let location = r.location.unwrap_or("");
    let body = r.body.unwrap_or("");
    (m.status.is_empty() || m.status.contains(&r.status))
        && m.location_matches
            .as_deref()
            .is_none_or(|p| r.location.is_some() && regex_matches(p, location))
        && m.location_not_matches
            .as_deref()
            .is_none_or(|p| !regex_matches(p, location))
        && m.cookie_set
            .as_deref()
            .is_none_or(|c| r.set_cookie_names.iter().any(|n| n == c))
        && m.body_contains.as_deref().is_none_or(|t| body.contains(t))
        && m.body_not_contains.as_deref().is_none_or(|t| !body.contains(t))
}

pub fn any(set: &MatcherSet, r: &ResponseView<'_>) -> bool {
    set.any_of.iter().any(|m| matches(m, r))
}

/// Une condition de l'ensemble a-t-elle besoin du corps de la réponse ?
pub fn needs_body(set: &MatcherSet) -> bool {
    set.any_of
        .iter()
        .any(|m| m.body_contains.is_some() || m.body_not_contains.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> Matcher {
        Matcher::default()
    }

    #[test]
    fn all_properties_must_hold() {
        let names = vec!["SESSID".to_string()];
        let r = ResponseView {
            status: 302,
            location: Some("/home"),
            set_cookie_names: &names,
            body: None,
        };
        let ok = Matcher {
            status: vec![302, 303],
            location_not_matches: Some("^/login".into()),
            cookie_set: Some("SESSID".into()),
            ..m()
        };
        assert!(matches(&ok, &r));
        assert!(!matches(
            &Matcher {
                status: vec![200],
                ..ok.clone()
            },
            &r
        ));
        assert!(!matches(
            &Matcher {
                cookie_set: Some("X".into()),
                ..ok.clone()
            },
            &r
        ));
        assert!(!matches(
            &Matcher {
                location_matches: Some("^/login".into()),
                ..m()
            },
            &r
        ));
    }

    #[test]
    fn location_matches_requires_a_location() {
        let r = ResponseView {
            status: 200,
            location: None,
            set_cookie_names: &[],
            body: Some("x"),
        };
        assert!(!matches(
            &Matcher {
                location_matches: Some(".*".into()),
                ..m()
            },
            &r
        ));
        assert!(matches(
            &Matcher {
                location_not_matches: Some("^/login".into()),
                ..m()
            },
            &r
        ));
    }

    #[test]
    fn body_markers() {
        let r = ResponseView {
            status: 401,
            location: None,
            set_cookie_names: &[],
            body: Some("Identifiants invalides"),
        };
        let set = MatcherSet {
            any_of: vec![Matcher {
                status: vec![401],
                body_contains: Some("invalides".into()),
                ..m()
            }],
        };
        assert!(any(&set, &r) && needs_body(&set));
        let r = ResponseView {
            body: Some("ok"),
            ..r
        };
        assert!(!any(&set, &r));
    }
}
