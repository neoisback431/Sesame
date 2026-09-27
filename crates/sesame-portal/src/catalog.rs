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

pub fn render(user: &UserIdentity, tiles: &[Tile<'_>], scheme: &str) -> String {
    let name = user.display_name.as_deref().unwrap_or(&user.user_key);
    let mut body = format!(
        "<h1>Mes applications</h1><p class=\"muted\">Connecté en tant que {}</p>",
        escape(name)
    );
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
                    "<li class=\"tile\"><div><strong>{}</strong><br>{desc}<br>\
<span class=\"warn\">Connexion impossible : contactez votre administrateur.</span></div></li>",
                    escape(&d.metadata.name)
                ));
            } else {
                body.push_str(&format!(
                    "<li class=\"tile\"><a href=\"{scheme}://{}/\"><strong>{}</strong><br>{desc}</a></li>",
                    escape(&d.spec.public.host),
                    escape(&d.metadata.name)
                ));
            }
        }
        body.push_str("</ul>");
    }
    body.push_str(
        "<form class=\"logout\" method=\"post\" action=\"/auth/logout\"><button type=\"submit\">Se déconnecter</button></form>",
    );
    page("Mes applications", &body)
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
        let html = render(&u, &tiles(&ds, &u, &[account(AccountStatus::Active)]), "https");
        assert!(html.contains("href=\"https://fake-app.sesame.localhost:8443/\""));
        assert!(html.contains("Alice &lt;admin&gt;"));
    }
}
