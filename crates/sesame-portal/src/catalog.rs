// SPDX-License-Identifier: Apache-2.0
//! Page « Mes applications » : applis habilitées pour lesquelles l'utilisateur a un compte.

use sesame_core::descriptor::AppDescriptor;
use sesame_core::html::{escape, page};
use sesame_core::identity::UserIdentity;
use sesame_core::ports::{AccountStatus, AppAccount};

#[derive(Debug)]
pub struct Tile<'a> {
    pub descriptor: &'a AppDescriptor,
    /// Dernier rejeu en échec : tuile affichée mais signalée, non cliquable.
    pub failed: bool,
}

/// Habilité (descripteur) ET compte `active` ou `failed` (registre). `disabled` est masqué.
pub fn tiles<'a>(
    descriptors: &'a [AppDescriptor],
    user: &UserIdentity,
    accounts: &[AppAccount],
) -> Vec<Tile<'a>> {
    descriptors
        .iter()
        .filter(|d| d.spec.access.allows(&user.user_key, &user.groups))
        .filter_map(|d| {
            let account = accounts.iter().find(|a| a.app_id == d.metadata.id)?;
            match account.status {
                AccountStatus::Active => Some(Tile {
                    descriptor: d,
                    failed: false,
                }),
                AccountStatus::Failed => Some(Tile {
                    descriptor: d,
                    failed: true,
                }),
                AccountStatus::Disabled => None,
            }
        })
        .collect()
}

/// Initiale affichée dans la pastille de la tuile.
fn initial(name: &str) -> String {
    name.chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect())
        .unwrap_or_else(|| "?".into())
}

/// `admin_url` : lien « Administration » affiché aux membres du groupe d'administrateurs
/// (`SESAME_ADMIN_URL` configurée et utilisateur dans `SESAME_ADMIN_GROUP`), `None` sinon.
pub fn render(
    user: &UserIdentity,
    tiles: &[Tile<'_>],
    scheme: &str,
    portal_url: &str,
    admin_url: Option<&str>,
) -> String {
    let name = user.display_name.as_deref().unwrap_or(&user.user_key);
    let mut body = format!(
        "<h1>Mes applications</h1><p class=\"muted\">Connecté en tant que {}</p>",
        escape(name)
    );
    if let Some(url) = admin_url {
        body.push_str(&format!(
            "<p><a class=\"button\" href=\"{}\">Administration</a></p>",
            escape(url)
        ));
    }
    if tiles.is_empty() {
        body.push_str("<p>Aucune application ne vous est attribuée pour le moment.</p>");
    } else {
        body.push_str("<ul class=\"tiles\">");
        for t in tiles {
            let d = t.descriptor;
            let desc = d
                .metadata
                .description
                .as_deref()
                .map(|s| format!("<span class=\"desc\">{}</span>", escape(s)))
                .unwrap_or_default();
            if t.failed {
                body.push_str(&format!(
                    "<li class=\"tile\"><div><span class=\"ico\" aria-hidden=\"true\">{}</span><span>\
<strong>{}</strong><br>{desc}<br>\
<span class=\"warn\">Connexion impossible : contactez votre administrateur.</span></span></div></li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name)
                ));
            } else {
                body.push_str(&format!(
                    "<li class=\"tile\"><a href=\"{scheme}://{}{}\"><span class=\"ico\" aria-hidden=\"true\">{}</span>\
<span><strong>{}</strong><br>{desc}</span></a></li>",
                    escape(&d.spec.public.host),
                    escape(&d.spec.public.start_path),
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name)
                ));
            }
        }
        body.push_str("</ul>");
    }
    body.push_str(
        "<form class=\"logout\" method=\"post\" action=\"/auth/logout\"><button type=\"submit\">Se déconnecter</button></form>",
    );
    page("Mes applications", &body, portal_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_APP: &str = include_str!("../../../descriptors/fake-app.yaml");

    fn user(groups: &[&str]) -> UserIdentity {
        UserIdentity {
            issuer: "i".into(),
            subject: "s".into(),
            user_key: "alice".into(),
            display_name: Some("Alice <admin>".into()),
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    fn account(status: AccountStatus) -> AppAccount {
        AppAccount {
            app_id: "fake-app".into(),
            user_key: "alice".into(),
            status,
            status_reason: None,
            last_login_at: None,
        }
    }

    #[test]
    fn requires_access_and_account() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let active = [account(AccountStatus::Active)];
        assert_eq!(tiles(&ds, &user(&["fake-app-users"]), &active).len(), 1);
        assert!(tiles(&ds, &user(&["autre"]), &active).is_empty(), "non habilité");
        assert!(
            tiles(&ds, &user(&["fake-app-users"]), &[]).is_empty(),
            "sans compte"
        );
        let disabled = [account(AccountStatus::Disabled)];
        assert!(tiles(&ds, &user(&["fake-app-users"]), &disabled).is_empty());
        let failed = [account(AccountStatus::Failed)];
        assert!(tiles(&ds, &user(&["fake-app-users"]), &failed)[0].failed);
    }

    #[test]
    fn renders_escaped_links() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let active = [account(AccountStatus::Active)];
        let html = render(
            &u,
            &tiles(&ds, &u, &active),
            "https",
            "https://sesame.test/",
            None,
        );
        assert!(html.contains("href=\"https://fake-app.sesame.localhost:8443/\""));
        assert!(!html.contains("Administration"));

        // Page d'arrivée : la tuile y mène directement (échappée).
        let mut d = AppDescriptor::from_yaml(FAKE_APP).unwrap();
        d.spec.public.start_path = "/chat?a=1&b=\"x".into();
        let ds = vec![d];
        let html = render(
            &u,
            &tiles(&ds, &u, &active),
            "https",
            "https://sesame.test/",
            None,
        );
        assert!(html.contains("href=\"https://fake-app.sesame.localhost:8443/chat?a=1&amp;b=&quot;x\""));
        assert!(html.contains("<span class=\"ico\" aria-hidden=\"true\">A</span>"));
        assert!(html.contains("https://sesame.test/static/logo-64.png"));
        assert!(html.contains("Alice &lt;admin&gt;"));
    }

    #[test]
    fn shows_admin_link_only_when_given() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let active = [account(AccountStatus::Active)];
        let t = tiles(&ds, &u, &active);
        let html = render(
            &u,
            &t,
            "https",
            "https://sesame.test/",
            Some("https://admin.sesame.test/"),
        );
        assert!(html.contains("<a class=\"button\" href=\"https://admin.sesame.test/\">Administration</a>"));
    }
}
