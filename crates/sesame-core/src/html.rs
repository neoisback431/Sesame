// SPDX-License-Identifier: Apache-2.0
//! Pages HTML minimales servies par Sesame (portail, erreurs du proxy).

/// Échappe un texte pour l'insérer dans du HTML (contenu ou attribut entre guillemets).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Ressources statiques (logo, favicon, bannière), embarquées dans le binaire.
/// Générées depuis `ressources/` par `scripts/build_web_assets.py`.
const ASSETS: &[(&str, &str, &[u8])] = &[
    (
        "logo-64.png",
        "image/png",
        include_bytes!("../assets/logo-64.png"),
    ),
    (
        "favicon-32.png",
        "image/png",
        include_bytes!("../assets/favicon-32.png"),
    ),
    (
        "banner.webp",
        "image/webp",
        include_bytes!("../assets/banner.webp"),
    ),
];

/// Ressource statique par nom : (type MIME, contenu).
pub fn asset(name: &str) -> Option<(&'static str, &'static [u8])> {
    ASSETS
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, mime, bytes)| (*mime, *bytes))
}

/// URL d'une ressource statique, servie par le portail sous `/static/`.
/// `portal_url` : URL publique du portail (les pages du proxy, servies sur les hôtes
/// des applis, pointent vers le portail pour ne jamais masquer un chemin de l'appli).
pub fn asset_url(portal_url: &str, name: &str) -> String {
    format!("{}/static/{name}", portal_url.trim_end_matches('/'))
}

/// Page complète. `title` est échappé ; `body` doit déjà être du HTML sûr.
pub fn page(title: &str, body: &str, portal_url: &str) -> String {
    format!(
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title} · Sesame</title><link rel=\"icon\" type=\"image/png\" href=\"{favicon}\">\
<style>{STYLE}</style></head><body><header><a class=\"brand\" href=\"{home}\">\
<img src=\"{logo}\" alt=\"\" width=\"32\" height=\"32\"><span><b>SE</b>same</span></a>\
<span class=\"tagline\">SEcure SSO Proxy</span></header><main>{body}</main></body></html>",
        title = escape(title),
        favicon = escape(&asset_url(portal_url, "favicon-32.png")),
        logo = escape(&asset_url(portal_url, "logo-64.png")),
        home = escape(portal_url),
    )
}

/// Page d'erreur générique : jamais de contenu venant d'une appli cible.
pub fn error_page(title: &str, message: &str, correlation_id: &str, portal_url: &str) -> String {
    page(
        title,
        &format!(
            "<div class=\"card\"><h1>{}</h1><p>{}</p><p class=\"muted\">Référence : <code>{}</code></p>\
<p><a class=\"button\" href=\"{}\">Retour à mes applications</a></p></div>",
            escape(title),
            escape(message),
            escape(correlation_id),
            escape(portal_url),
        ),
        portal_url,
    )
}

/// Couleurs reprises du logo : bleu nuit, bleu, cyan.
const STYLE: &str = ":root{--navy:#0a1f5c;--blue:#1464c0;--cyan:#13b5cf;--ink:#15213b;--muted:#5b6475;\
--line:#d9e1ee;--bg:#f3f6fb}\
body{font-family:system-ui,sans-serif;margin:0;background:var(--bg);color:var(--ink)}\
header{background:linear-gradient(90deg,var(--navy),var(--blue) 65%,var(--cyan));color:#fff;\
padding:10px 24px;display:flex;align-items:center;gap:16px}\
.brand{display:flex;align-items:center;gap:10px;color:#fff;text-decoration:none;font-size:1.25em;\
letter-spacing:.02em}.brand b{color:#8fe3f0}.brand img{border-radius:8px}\
.tagline{color:#cfe6f7;font-size:.85em;border-left:1px solid rgba(255,255,255,.35);padding-left:16px}\
main{max-width:880px;margin:32px auto;padding:0 16px}h1{color:var(--navy)}\
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px;padding:0;list-style:none}\
.tile a,.tile div{display:flex;gap:12px;align-items:flex-start;background:#fff;border:1px solid var(--line);\
border-radius:10px;padding:16px;color:inherit;text-decoration:none;min-height:64px;\
box-shadow:0 1px 2px rgba(10,31,92,.06)}\
.tile a:hover{border-color:var(--cyan);box-shadow:0 4px 14px rgba(20,100,192,.15)}\
.tile .ico{flex:none;width:40px;height:40px;border-radius:10px;display:grid;place-items:center;color:#fff;\
font-weight:700;background:linear-gradient(135deg,var(--blue),var(--cyan))}\
.tile .desc,.muted{color:var(--muted);font-size:.9em}.warn{color:#a03c00;font-size:.9em}\
.tile .unavailable{opacity:.55;box-shadow:none}\
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:24px}\
.hero{text-align:center}.hero img{max-width:100%;height:auto;border-radius:14px}\
button,a.button{display:inline-block;padding:7px 16px;border:0;border-radius:6px;background:var(--blue);\
color:#fff;font:inherit;text-decoration:none;cursor:pointer}button:hover,a.button:hover{background:var(--navy)}\
form.disconnect{text-align:right;margin-top:4px}\
button.link{background:none;padding:0;color:var(--muted);font-size:.85em;text-decoration:underline}\
button.link:hover{background:none;color:var(--navy)}\
form.logout{margin-top:32px}\
.notice{background:#e8f4fb;border:1px solid var(--cyan);border-radius:8px;padding:10px 14px}\
.card+.card{margin-top:16px}label{display:block;margin:12px 0 4px;font-weight:600}\
input[type=text],input[type=password],textarea{width:100%;box-sizing:border-box;padding:8px;\
border:1px solid var(--line);border-radius:6px;font:inherit}.error{color:#a03c00;font-weight:600}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup() {
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        let p = error_page("Erreur <script>", "msg", "id-1", "https://p/");
        assert!(p.contains("Erreur &lt;script&gt;") && !p.contains("<script>"));
    }

    #[test]
    fn pages_point_to_portal_assets() {
        let p = error_page("Erreur", "msg", "id-1", "https://sesame.example/");
        assert!(p.contains("src=\"https://sesame.example/static/logo-64.png\""));
        assert!(p.contains("href=\"https://sesame.example/static/favicon-32.png\""));
        for name in ["logo-64.png", "favicon-32.png", "banner.webp"] {
            let (_, bytes) = asset(name).expect(name);
            assert!(!bytes.is_empty());
        }
        assert!(asset("../Cargo.toml").is_none());
    }
}
