// SPDX-License-Identifier: Apache-2.0
//! Page « Mes applications » : applis habilitées pour lesquelles l'utilisateur a un compte.

use sesame_core::descriptor::AppDescriptor;
use sesame_core::html::{escape, page};
use sesame_core::identity::UserIdentity;
use sesame_core::ports::{effective_account, AccessRequest, AccessRequestKind, AccountStatus, AppAccount};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TileState {
    /// Compte actif : tuile cliquable, avec un bouton pour forcer la déconnexion.
    Active,
    /// Compte actif mais connexion automatique suspendue après « Déconnecter » (ADR 0033) :
    /// la tuile reste cliquable et rétablit la connexion automatique.
    Suspended,
    /// Dernier rejeu en échec : tuile affichée mais signalée, non cliquable.
    Failed,
    /// Habilité mais sans compte : tuile grisée, non cliquable, avec « Demander l'accès » (ADR 0029).
    NoAccount,
    /// Identifiants fournis, en attente d'activation par un administrateur : tuile grisée.
    PendingApproval,
    /// Demande « je n'ai pas de compte » ouverte : un administrateur doit créer le compte.
    Requested,
}

#[derive(Debug)]
pub struct Tile<'a> {
    pub descriptor: &'a AppDescriptor,
    /// État du compte utilisé (choisi, sinon par défaut, ADR 0034).
    pub state: TileState,
    /// Comptes entre lesquels l'utilisateur peut choisir (identifiant, libellé) : vide s'il
    /// n'en a qu'un. Seuls les comptes actifs ou en échec y figurent.
    pub choices: Vec<(String, String)>,
    /// Compte utilisé, quand il y a un choix à proposer.
    pub current: Option<String>,
}

/// Habilité (descripteur). L'état de la tuile est celui du compte utilisé (choisi, sinon par
/// défaut, ADR 0034). Tous les comptes désactivés : masqué ; `active` et `failed` affichés
/// normalement ; sans compte, affiché grisé (voir ADR 0022) plutôt que masqué ; une demande
/// d'accès en cours (ADR 0029) est signalée sur la tuile grisée. `selected` : comptes choisis
/// par l'utilisateur, (appli, compte).
pub fn tiles<'a>(
    descriptors: &'a [AppDescriptor],
    user: &UserIdentity,
    accounts: &[AppAccount],
    requests: &[AccessRequest],
    selected: &[(String, String)],
) -> Vec<Tile<'a>> {
    descriptors
        .iter()
        .filter(|d| d.spec.access.allows(&user.user_key, &user.groups))
        .filter_map(|d| {
            let id = &d.metadata.id;
            let own: Vec<AppAccount> = accounts.iter().filter(|a| &a.app_id == id).cloned().collect();
            let choices: Vec<(String, String)> = own
                .iter()
                .filter(|a| matches!(a.status, AccountStatus::Active | AccountStatus::Failed))
                .map(|a| (a.account_id.clone(), a.display_label().to_owned()))
                .collect();
            let chosen = selected.iter().find(|(a, _)| a == id).map(|(_, c)| c.as_str());
            let state = match effective_account(own, chosen) {
                Some(a) => {
                    let state = match a.status {
                        AccountStatus::Active => TileState::Active,
                        AccountStatus::Failed => TileState::Failed,
                        AccountStatus::Disabled => return None,
                        AccountStatus::Pending => TileState::PendingApproval,
                    };
                    if choices.len() > 1 {
                        return Some(Tile {
                            descriptor: d,
                            state,
                            choices,
                            current: Some(a.account_id),
                        });
                    }
                    state
                }
                None if requests
                    .iter()
                    .any(|r| &r.app_id == id && r.kind == AccessRequestKind::NoAccount) =>
                {
                    TileState::Requested
                }
                None => TileState::NoAccount,
            };
            Some(Tile {
                descriptor: d,
                state,
                choices: Vec::new(),
                current: None,
            })
        })
        .collect()
}

/// Sélecteur de compte (ADR 0034), affiché seulement quand l'utilisateur en a plusieurs.
fn account_picker(t: &Tile<'_>) -> String {
    if t.choices.len() < 2 {
        return String::new();
    }
    let options: String = t
        .choices
        .iter()
        .map(|(id, label)| {
            let selected = if t.current.as_deref() == Some(id.as_str()) {
                " selected"
            } else {
                ""
            };
            format!(
                "<option value=\"{}\"{selected}>{}</option>",
                escape(id),
                escape(label)
            )
        })
        .collect();
    format!(
        "<form class=\"accounts\" method=\"post\" action=\"/apps/{}/account\">\
<label>Compte <select name=\"account\">{options}</select></label> \
<button type=\"submit\" class=\"link\">Utiliser</button></form>",
        escape(&t.descriptor.metadata.id)
    )
}

/// Marque « suspendue » les tuiles actives dont la connexion automatique est suspendue.
pub fn mark_suspended(tiles: &mut [Tile<'_>], suspended: &[String]) {
    for t in tiles
        .iter_mut()
        .filter(|t| t.state == TileState::Active && suspended.contains(&t.descriptor.metadata.id))
    {
        t.state = TileState::Suspended;
    }
}

/// Messages de retour d'une demande d'accès, désignés par un code fixe dans l'URL
/// (`/?request=<code>`) : aucun texte fourni par l'appelant n'est jamais affiché.
pub fn notice_text(code: &str) -> Option<&'static str> {
    Some(match code {
        "credentials" => {
            "Vos identifiants sont enregistrés. Un administrateur doit maintenant activer votre compte."
        }
        "no_account" => "Votre demande est transmise : un administrateur va créer votre compte.",
        "exists" => "Un compte existe déjà pour vous sur cette application : aucune demande n'a été créée.",
        "account" => "Compte changé : l'application l'utilisera à sa prochaine ouverture.",
        _ => return None,
    })
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
/// `notice` : code d'un message de retour d'une demande d'accès (voir [`notice_text`]).
pub fn render(
    user: &UserIdentity,
    tiles: &[Tile<'_>],
    portal_url: &str,
    admin_url: Option<&str>,
    notice: Option<&str>,
) -> String {
    let name = user.display_name.as_deref().unwrap_or(&user.user_key);
    let mut body = format!(
        "<h1>Mes applications</h1><p class=\"muted\">Connecté en tant que {}</p>",
        escape(name)
    );
    if let Some(text) = notice.and_then(notice_text) {
        body.push_str(&format!(
            "<p class=\"notice\" role=\"status\">{}</p>",
            escape(text)
        ));
    }
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
<span class=\"warn\">Connexion impossible : contactez votre administrateur.</span></span></div>{}</li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name),
                    account_picker(t),
                )),
                TileState::NoAccount => body.push_str(&format!(
                    "<li class=\"tile\"><div class=\"unavailable\"><span class=\"ico\" aria-hidden=\"true\">{}</span><span>\
<strong>{}</strong><br>{desc}<br>\
<span class=\"muted\">Vous n'avez pas de compte sur cette application.</span></span></div>\
<form class=\"disconnect\" method=\"get\" action=\"/apps/{}/request\">\
<button type=\"submit\" class=\"link\">Demander l'accès</button></form></li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name),
                    escape(&d.metadata.id),
                )),
                TileState::PendingApproval | TileState::Requested => body.push_str(&format!(
                    "<li class=\"tile\"><div class=\"unavailable\"><span class=\"ico\" aria-hidden=\"true\">{}</span><span>\
<strong>{}</strong><br>{desc}<br>\
<span class=\"muted\">{}</span></span></div></li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name),
                    if t.state == TileState::PendingApproval {
                        "Demande en cours : un administrateur doit activer votre compte."
                    } else {
                        "Demande envoyée : un administrateur va créer votre compte."
                    },
                )),
                // La tuile passe par le portail (`/apps/<id>/open`) : un clic rétablit la connexion
                // automatique d'une appli suspendue avant d'ouvrir l'appli (ADR 0033).
                TileState::Active => body.push_str(&format!(
                    "<li class=\"tile\"><a href=\"/apps/{id}/open\" target=\"_blank\" rel=\"noopener noreferrer\">\
<span class=\"ico\" aria-hidden=\"true\">{}</span><span><strong>{}</strong><br>{desc}</span></a>\
<form class=\"disconnect\" method=\"post\" action=\"/apps/{id}/disconnect\">\
<button type=\"submit\" class=\"link\">Déconnecter</button></form>{}</li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name),
                    account_picker(t),
                    id = escape(&d.metadata.id),
                )),
                TileState::Suspended => body.push_str(&format!(
                    "<li class=\"tile\"><a href=\"/apps/{id}/open\" target=\"_blank\" rel=\"noopener noreferrer\">\
<span class=\"ico\" aria-hidden=\"true\">{}</span><span><strong>{}</strong><br>{desc}<br>\
<span class=\"muted\">Déconnecté : cliquez pour vous reconnecter automatiquement.</span></span></a>{}</li>",
                    escape(&initial(&d.metadata.name)),
                    escape(&d.metadata.name),
                    account_picker(t),
                    id = escape(&d.metadata.id),
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
            email: None,
            groups: groups.iter().map(|g| g.to_string()).collect(),
        }
    }

    fn account(status: AccountStatus) -> AppAccount {
        AppAccount::new(
            &sesame_core::ports::AccountKey::default_of("fake-app", "alice"),
            status,
            true,
        )
    }

    fn extra(id: &str, label: Option<&str>, status: AccountStatus) -> AppAccount {
        let mut a = AppAccount::new(
            &sesame_core::ports::AccountKey::new("fake-app", "alice", id),
            status,
            false,
        );
        a.label = label.map(str::to_owned);
        a
    }

    #[test]
    fn several_accounts_show_a_picker_with_the_account_in_use() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let accounts = [
            account(AccountStatus::Active),
            extra("admin", Some("Admin <prod>"), AccountStatus::Active),
            extra("off", Some("Ancien"), AccountStatus::Disabled),
        ];

        let t = tiles(&ds, &u, &accounts, &[], &[]);
        assert_eq!(t[0].state, TileState::Active);
        assert_eq!(t[0].current.as_deref(), Some("default"));
        let ids: Vec<&str> = t[0].choices.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, ["default", "admin"], "compte désactivé exclu");
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(html.contains("action=\"/apps/fake-app/account\""));
        assert!(html.contains("<option value=\"default\" selected>default</option>"));
        assert!(html.contains("<option value=\"admin\">Admin &lt;prod&gt;</option>"));
        assert!(!html.contains("Ancien"));

        // Compte choisi : il devient le compte utilisé, et son état fait celui de la tuile.
        let mut accounts = accounts;
        accounts[1].status = AccountStatus::Failed;
        let selected = [("fake-app".to_owned(), "admin".to_owned())];
        let t = tiles(&ds, &u, &accounts, &[], &selected);
        assert_eq!(t[0].state, TileState::Failed);
        assert_eq!(t[0].current.as_deref(), Some("admin"));
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(
            html.contains("action=\"/apps/fake-app/account\""),
            "le sélecteur reste proposé sur une tuile en échec"
        );

        // Un seul compte utilisable : pas de sélecteur.
        let t = tiles(&ds, &u, &[account(AccountStatus::Active)], &[], &[]);
        assert!(t[0].choices.is_empty() && t[0].current.is_none());
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(!html.contains("/account\""));

        // Tous les comptes désactivés : tuile masquée.
        let off = [
            account(AccountStatus::Disabled),
            extra("admin", None, AccountStatus::Disabled),
        ];
        assert!(tiles(&ds, &u, &off, &[], &[]).is_empty());
    }

    #[test]
    fn requires_access_shows_state_by_account() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let active = [account(AccountStatus::Active)];
        assert_eq!(tiles(&ds, &user(&["fake-app-users"]), &active, &[], &[]).len(), 1);
        assert!(
            tiles(&ds, &user(&["autre"]), &active, &[], &[]).is_empty(),
            "non habilité"
        );

        // Habilité mais sans compte : grisé, pas masqué (ADR 0022).
        let sans_compte = tiles(&ds, &user(&["fake-app-users"]), &[], &[], &[]);
        assert_eq!(sans_compte.len(), 1);
        assert_eq!(sans_compte[0].state, TileState::NoAccount);

        let disabled = [account(AccountStatus::Disabled)];
        assert!(tiles(&ds, &user(&["fake-app-users"]), &disabled, &[], &[]).is_empty());
        let failed = [account(AccountStatus::Failed)];
        assert_eq!(
            tiles(&ds, &user(&["fake-app-users"]), &failed, &[], &[])[0].state,
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
            &tiles(&ds, &u, &active, &[], &[]),
            "https://sesame.test/",
            None,
            None,
        );
        assert!(html.contains("href=\"/apps/fake-app/open\""));
        assert!(
            html.contains("target=\"_blank\" rel=\"noopener noreferrer\""),
            "nouvel onglet"
        );
        assert!(
            html.contains("action=\"/apps/fake-app/disconnect\""),
            "bouton de déconnexion"
        );
        assert!(!html.contains("Administration"));

        // La page d'arrivée (`start_path`) n'apparaît plus : la route `open` y redirige.
        assert!(!html.contains("fake-app.sesame.localhost"));
        assert!(html.contains("<span class=\"ico\" aria-hidden=\"true\">A</span>"));
        assert!(html.contains("https://sesame.test/static/logo-64.png"));
        assert!(html.contains("Alice &lt;admin&gt;"));
    }

    #[test]
    fn renders_grayed_tile_without_account() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let t = tiles(&ds, &u, &[], &[], &[]);
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(html.contains("class=\"unavailable\""));
        assert!(html.contains("Vous n'avez pas de compte sur cette application."));
        // Grisée, non cliquable : pas de lien vers l'appli ni de bouton de déconnexion.
        assert!(!html.contains("href=\"/apps/fake-app/open\""));
        assert!(!html.contains("action=\"/apps/fake-app/disconnect\""));
    }

    #[test]
    fn suspended_tile_stays_clickable_without_disconnect_button() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let active = [account(AccountStatus::Active)];
        let mut t = tiles(&ds, &u, &active, &[], &[]);
        mark_suspended(&mut t, &["autre-appli".to_owned()]);
        assert_eq!(t[0].state, TileState::Active, "autre appli : sans effet");
        mark_suspended(&mut t, &["fake-app".to_owned()]);
        assert_eq!(t[0].state, TileState::Suspended);
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(html.contains("href=\"/apps/fake-app/open\""), "reste cliquable");
        assert!(html.contains("cliquez pour vous reconnecter"));
        assert!(!html.contains("action=\"/apps/fake-app/disconnect\""));

        // Un compte en échec n'est jamais « suspendu ».
        let failed = [account(AccountStatus::Failed)];
        let mut t = tiles(&ds, &u, &failed, &[], &[]);
        mark_suspended(&mut t, &["fake-app".to_owned()]);
        assert_eq!(t[0].state, TileState::Failed);
    }

    #[test]
    fn shows_admin_link_only_when_given() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let active = [account(AccountStatus::Active)];
        let t = tiles(&ds, &u, &active, &[], &[]);
        let html = render(
            &u,
            &t,
            "https://sesame.test/",
            Some("https://admin.sesame.test/"),
            None,
        );
        assert!(html.contains("<a class=\"button\" href=\"https://admin.sesame.test/\">Administration</a>"));
    }

    #[test]
    fn access_request_states_and_notices() {
        let ds = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let u = user(&["fake-app-users"]);
        let request = |kind| AccessRequest {
            app_id: "fake-app".into(),
            user_key: "alice".into(),
            kind,
            note: None,
            created_at: std::time::SystemTime::now(),
        };

        // Sans compte ni demande : bouton « Demander l'accès » vers le formulaire du portail.
        let t = tiles(&ds, &u, &[], &[], &[]);
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(html.contains("action=\"/apps/fake-app/request\""));
        assert!(html.contains("Demander l'accès"));

        // Demande « sans compte » ouverte : grisé, plus de bouton.
        let t = tiles(&ds, &u, &[], &[request(AccessRequestKind::NoAccount)], &[]);
        assert_eq!(t[0].state, TileState::Requested);
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(!html.contains("action=\"/apps/fake-app/request\""));
        assert!(html.contains("Demande envoyée"));

        // Compte en attente d'activation (identifiants fournis).
        let t = tiles(&ds, &u, &[account(AccountStatus::Pending)], &[], &[]);
        assert_eq!(t[0].state, TileState::PendingApproval);
        let html = render(&u, &t, "https://sesame.test/", None, None);
        assert!(html.contains("Demande en cours"));
        assert!(!html.contains("href=\"/apps/fake-app/open\""));

        // Message de retour : code fixe uniquement, jamais de texte de l'appelant.
        let html = render(&u, &t, "https://sesame.test/", None, Some("credentials"));
        assert!(html.contains("class=\"notice\""));
        let html = render(&u, &t, "https://sesame.test/", None, Some("<script>x</script>"));
        assert!(!html.contains("class=\"notice\"") && !html.contains("<script>x"));
    }
}
