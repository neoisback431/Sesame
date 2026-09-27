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

/// Page complète. `title` est échappé ; `body` doit déjà être du HTML sûr.
pub fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title} · Sesame</title><style>{STYLE}</style></head>\
<body><header><strong>Sesame</strong></header><main>{body}</main></body></html>",
        title = escape(title),
    )
}

/// Page d'erreur générique : jamais de contenu venant d'une appli cible.
pub fn error_page(title: &str, message: &str, correlation_id: &str, portal_url: &str) -> String {
    page(
        title,
        &format!(
            "<h1>{}</h1><p>{}</p><p class=\"muted\">Référence : <code>{}</code></p>\
<p><a href=\"{}\">Retour à mes applications</a></p>",
            escape(title),
            escape(message),
            escape(correlation_id),
            escape(portal_url),
        ),
    )
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2330}\
header{background:#1d2330;color:#fff;padding:12px 24px}main{max-width:880px;margin:32px auto;padding:0 16px}\
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px;padding:0;list-style:none}\
.tile a,.tile div{display:block;background:#fff;border:1px solid #d9dde5;border-radius:8px;padding:16px;\
color:inherit;text-decoration:none;min-height:64px}.tile a:hover{border-color:#3b6ef5}\
.tile .desc,.muted{color:#5b6475;font-size:.9em}.warn{color:#a03c00;font-size:.9em}\
form.logout{margin-top:32px}button{padding:6px 14px}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup() {
        assert_eq!(
            escape("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        let p = error_page("Erreur <b>", "msg", "id-1", "https://p/");
        assert!(p.contains("Erreur &lt;b&gt;") && !p.contains("<b>"));
    }
}
