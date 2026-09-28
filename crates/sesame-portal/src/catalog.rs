// SPDX-License-Identifier: Apache-2.0
//! Page « Mes applications » : applis habilitées pour lesquelles l'utilisateur a un compte.

use sesame_core::descriptor::AppDescriptor;
use sesame_core::html::{escape, page};
use sesame_core::identity::UserIdentity;
use sesame_core::ports::{AccountStatus, AppAccount};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileState {
    /// Compte actif : tuile cliquable, avec un bouton pour forcer la déconnexion.
    Active,
    /// Dernier rejeu en échec : tuile affichée mais signalée, non cliquable.
    Failed,
    /// Habilité mais sans compte : tuile grisée, non cliquable.
    NoAccount,
}

#[derive(Debug)]
pub struct Tile<'a> {
    pub descriptor: &'a AppDescriptor,
    pub state: TileState,
}

/// Habilité (descripteur). `disabled` est masqué ; `active` et `failed` affichés normalement ;
/// sans compte, affiché grisé (voir ADR 0022) plutôt que masqué.
pub fn tiles<'a>(
    descriptors: &'a [AppDescriptor],
    user: &UserIdentity,
    accounts: &[AppAccount],
) -> Vec<Tile<'a>> {
    descriptors
        .iter()
        .filter(|d| d.spec.access.allows(&user.user_key, &user.groups))
        .filter_map(|d| {
            let state = match accounts.iter().find(|a| a.app_id == d.metadata.id) {
                Some(a) => match a.status {
                    AccountStatus::Active => TileState::Active,
                    AccountStatus::Failed => TileState::Failed,
                    AccountStatus::Disabled => return None,
                },
                None => TileState::NoAccount,
            };
            Some(Tile { descriptor: d, state })
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
            match t.state {
                TileState::Failed => body.push_str(&format!(
                    "<li class=\"tile\"><div><span class=\"ico\" aria-hidden=\"true\">{}</span><span>\
<strong>{}</strong><br>{desc}<br>\
<span class=\"warn\">Connexion impossible : contactez votre administrateur.</span></span></div></li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name)
                )),
                TileState::NoAccount => body.push_str(&format!(
                    "<li class=\"tile\"><div class=\"unavailable\"><span class=\"ico\" aria-hidden=\"true\">{}</span><span>\
<strong>{}</strong><br>{desc}<br>\
<span class=\"muted\">Vous n'avez pas de compte sur cette application.</span></span></div></li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name)
                )),
                TileState::Active => body.push_str(&format!(
                    "<li class=\"tile\"><a href=\"{scheme}://{}{}\" target=\"_blank\" rel=\"noopener noreferrer\">\
<span class=\"ico\" aria-hidden=\"true\">{}</span><span><strong>{}</strong><br>{desc}</span></a>\
<form class=\"disconnect\" method=\"post\" action=\"/apps/{}/disconnect\">\
<button type=\"submit\" class=\"link\">Déconnecter</button></form></li>",
                    escape(&d.spec.public.host),
                    escape(&d.spec.public.start_path),
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name),
                    escape(&d.metadata.id),
                )),
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
    fn requires_access_shows_state_by_account() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let active = [account(AccountStatus::Active)];
        assert_eq!(tiles(&ds, &user(&["fake-app-users"]), &active).len(), 1);
        assert!(tiles(&ds, &user(&["autre"]), &active).is_empty(), "non habilité");

        // Habilité mais sans compte : grisé, pas masqué (ADR 0022).
        let sans_compte = tiles(&ds, &user(&["fake-app-users"]), &[]);
        assert_eq!(sans_compte.len(), 1);
        assert_eq!(sans_compte[0].state, TileState::NoAccount);

        let disabled = [account(AccountStatus::Disabled)];
        assert!(tiles(&ds, &user(&["fake-app-users"]), &disabled).is_empty());
        let failed = [account(AccountStatus::Failed)];
        assert_eq!(
            tiles(&ds, &user(&["fake-app-users"]), &failed)[0].state,
            TileState::Failed
        );
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
        assert!(
            html.contains("target=\"_blank\" rel=\"noopener noreferrer\""),
            "nouvel onglet"
        );
        assert!(
            html.contains("action=\"/apps/fake-app/disconnect\""),
            "bouton de déconnexion"
        );
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
    fn renders_grayed_tile_without_account() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let t = tiles(&ds, &u, &[]);
        let html = render(&u, &t, "https", "https://sesame.test/", None);
        assert!(html.contains("class=\"unavailable\""));
        assert!(html.contains("Vous n'avez pas de compte sur cette application."));
        // Grisée, non cliquable : pas de lien vers l'appli ni de bouton de déconnexion.
        assert!(!html.contains("href=\"https://fake-app.sesame.localhost:8443/\""));
        assert!(!html.contains("action=\"/apps/fake-app/disconnect\""));
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
