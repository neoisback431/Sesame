// SPDX-License-Identifier: Apache-2.0
//! SAML 2.0 générique : SP-initiated SSO (liaison Redirect pour l'aller, POST pour le retour),
//! vérification de signature XML (xmlsec), extraction de l'identité selon un mapping
//! d'attributs configurable. Toute la vérification cryptographique (signature, audience,
//! `InResponseTo`, fenêtre de validité) est déléguée à `samael` : aucune manipulation de XML
//! signé n'est faite à la main ici.

use samael::metadata::EntityDescriptor;
use samael::schema::Assertion;
use samael::service_provider::{ServiceProvider, ServiceProviderBuilder};
use samael::traits::ToXml;
use serde::{Deserialize, Serialize};
use sesame_core::identity::{validate_user_key, UserIdentity};
use std::str::FromStr;

use crate::config::SamlConfig;
use crate::idp::PendingLogin;

#[derive(Debug, thiserror::Error)]
pub enum SamlError {
    #[error("configuration SAML : {0}")]
    Config(String),
    #[error("requête d'authentification : {0}")]
    Request(String),
    #[error("réponse SAML invalide : {0}")]
    Response(String),
    #[error("attributs : {0}")]
    Claims(String),
    #[error("métadonnées : {0}")]
    Metadata(String),
}

/// Partie de `PendingLogin` propre à SAML : l'identifiant de l'`AuthnRequest` émise, comparé
/// à `InResponseTo` dans la réponse (anti-rejeu, en plus de la vérification faite par `samael`).
#[derive(Serialize, Deserialize)]
pub struct SamlPending {
    pub request_id: String,
}

pub struct Saml {
    sp: ServiceProvider,
    idp_sso_url: String,
    /// Attribut portant la clé utilisateur (coffre, registre) ; `None` = NameID.
    user_key_attribute: Option<String>,
    email_attribute: Option<String>,
    groups_attribute: Option<String>,
}

impl Saml {
    pub fn new(cfg: &SamlConfig, acs_url: String) -> Result<Self, SamlError> {
        let idp_metadata = build_idp_metadata(&cfg.idp_entity_id, &cfg.idp_sso_url, &cfg.idp_cert_pem)?;
        let sp = ServiceProviderBuilder::default()
            .entity_id(Some(cfg.sp_entity_id.clone()))
            .acs_url(Some(acs_url))
            .idp_metadata(idp_metadata)
            .build()
            .map_err(|e| SamlError::Config(e.to_string()))?;
        Ok(Self {
            sp,
            idp_sso_url: cfg.idp_sso_url.clone(),
            user_key_attribute: cfg.user_key_attribute.clone(),
            email_attribute: cfg.email_attribute.clone(),
            groups_attribute: cfg.groups_attribute.clone(),
        })
    }

    /// URL de redirection vers l'IdP (liaison Redirect) et état à conserver jusqu'au retour.
    pub fn start(&self, return_to: String, expires_at: u64) -> Result<(String, PendingLogin), SamlError> {
        let mut req = self
            .sp
            .make_authentication_request(&self.idp_sso_url)
            .map_err(|e| SamlError::Request(e.to_string()))?;
        // Identifiant SAML : doit commencer par une lettre ou `_` (xsd:ID), jamais un chiffre.
        req.id = format!("_{}", uuid::Uuid::new_v4().simple());
        let csrf = uuid::Uuid::new_v4().to_string();
        let url = req
            .redirect(&csrf)
            .map_err(|e| SamlError::Request(e.to_string()))?
            .ok_or_else(|| SamlError::Request("URL de redirection manquante".into()))?;
        let pending = PendingLogin {
            csrf,
            return_to,
            expires_at,
            oidc: None,
            saml: Some(SamlPending { request_id: req.id }),
        };
        Ok((url.to_string(), pending))
    }

    /// Vérifie la réponse (signature, émetteur, audience, fenêtre de validité, `InResponseTo`)
    /// et construit l'identité à partir de l'assertion.
    pub fn finish(&self, saml_response_b64: &str, pending: &PendingLogin) -> Result<UserIdentity, SamlError> {
        let saml_pending = pending
            .saml
            .as_ref()
            .ok_or_else(|| SamlError::Response("état de connexion inattendu".into()))?;
        let assertion = self
            .sp
            .parse_base64_response(saml_response_b64, Some(&[saml_pending.request_id.as_str()]))
            .map_err(|e| SamlError::Response(e.to_string()))?;
        identity_from_assertion(
            &assertion,
            self.user_key_attribute.as_deref(),
            self.email_attribute.as_deref(),
            self.groups_attribute.as_deref(),
        )
    }

    /// Métadonnées XML du fournisseur de service, à déclarer chez l'IdP.
    pub fn metadata_xml(&self) -> Result<String, SamlError> {
        self.sp
            .metadata()
            .map_err(|e| SamlError::Metadata(e.to_string()))?
            .to_string()
            .map_err(|e| SamlError::Metadata(e.to_string()))
    }
}

/// Construit les métadonnées de l'IdP à partir de la configuration (URL de SSO, émetteur,
/// certificat de signature) : pas de récupération dynamique d'un document de métadonnées,
/// tout vient de variables d'environnement (cohérent avec le reste du projet).
fn build_idp_metadata(entity_id: &str, sso_url: &str, cert_pem: &str) -> Result<EntityDescriptor, SamlError> {
    let cert_b64 = pem_body(cert_pem)?;
    let xml = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>{cert_b64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        entity_id = xml_escape(entity_id),
        sso_url = xml_escape(sso_url),
    );
    EntityDescriptor::from_str(&xml).map_err(|e| SamlError::Config(e.to_string()))
}

/// Retire l'en-tête/pied PEM et les retours à la ligne : `samael` attend le corps base64 nu.
fn pem_body(pem: &str) -> Result<String, SamlError> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    if body.is_empty() {
        return Err(SamlError::Config("certificat IdP vide ou illisible".into()));
    }
    Ok(body)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Construit l'identité à partir d'une assertion déjà vérifiée (signature, émetteur, audience,
/// fenêtre de validité, anti-rejeu : tout est fait par `samael` avant l'appel).
fn identity_from_assertion(
    assertion: &Assertion,
    user_key_attribute: Option<&str>,
    email_attribute: Option<&str>,
    groups_attribute: Option<&str>,
) -> Result<UserIdentity, SamlError> {
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .map(|n| n.value.clone());

    let attributes: Vec<&samael::attribute::Attribute> = assertion
        .attribute_statements
        .iter()
        .flatten()
        .flat_map(|st| st.attributes.iter())
        .collect();
    let matches = |a: &&samael::attribute::Attribute, name: &str| {
        a.name.as_deref() == Some(name) || a.friendly_name.as_deref() == Some(name)
    };
    let first_value = |name: &str| -> Option<String> {
        attributes
            .iter()
            .find(|a| matches(a, name))
            .and_then(|a| a.values.first())
            .and_then(|v| v.value.clone())
    };
    let all_values = |name: &str| -> Vec<String> {
        attributes
            .iter()
            .filter(|a| matches(a, name))
            .flat_map(|a| a.values.iter())
            .filter_map(|v| v.value.clone())
            .collect()
    };

    let user_key = match user_key_attribute {
        Some(name) => {
            first_value(name).ok_or_else(|| SamlError::Claims(format!("attribut {name} absent")))?
        }
        None => name_id
            .clone()
            .ok_or_else(|| SamlError::Claims("NameID absent".into()))?,
    };
    validate_user_key(&user_key).map_err(SamlError::Claims)?;
    let groups = groups_attribute.map(all_values).unwrap_or_default();
    let display_name = email_attribute.and_then(first_value).or_else(|| name_id.clone());

    Ok(UserIdentity {
        issuer: assertion.issuer.value.clone().unwrap_or_default(),
        subject: name_id.unwrap_or_default(),
        user_key,
        display_name,
        groups,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use chrono::{Duration, Utc};
    use samael::attribute::{Attribute, AttributeValue};
    use samael::crypto::{Crypto, CryptoProvider};
    use samael::idp::{CertificateParams, IdentityProvider as TestIdp, KeyType, Rsa};
    use samael::schema::{
        Assertion as SchemaAssertion, AudienceRestriction, AuthnContext, AuthnContextClassRef,
        AuthnStatement, Conditions, Issuer, Response as SchemaResponse, Status, StatusCode, Subject,
        SubjectConfirmation, SubjectConfirmationData, SubjectNameID,
    };
    use samael::traits::ToXml;

    use super::*;

    /// Un attribut simple (une seule valeur), comme la plupart des IdP en émettent.
    struct TestAttribute<'a> {
        name: &'a str,
        value: &'a str,
    }

    /// Réponse SAML signée réaliste : fenêtre de validité correcte (contrairement au gabarit
    /// de test fourni par `samael`, qui la laisse vide et que le SP rejette donc toujours),
    /// signée avec la clé de l'IdP de test. Reproduit la forme d'`IdentityProvider::sign_authn_response`
    /// de `samael`, avec `Conditions`/`SubjectConfirmationData` complets.
    fn build_and_sign_response(
        idp: &TestIdp,
        idp_cert_der: &samael::crypto::CertificateDer,
        name_id: &str,
        request_id: &str,
        audience: &str,
        attributes: &[TestAttribute],
    ) -> SchemaResponse {
        let now = Utc::now();
        let issuer = Issuer {
            value: Some(IDP_ENTITY_ID.to_string()),
            ..Default::default()
        };
        let assertion = SchemaAssertion {
            id: samael::crypto::gen_saml_assertion_id(),
            issue_instant: now,
            version: "2.0".to_string(),
            issuer: issuer.clone(),
            signature: None,
            subject: Some(Subject {
                name_id: Some(SubjectNameID {
                    format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string()),
                    value: name_id.to_owned(),
                }),
                subject_confirmations: Some(vec![SubjectConfirmation {
                    method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                    name_id: None,
                    subject_confirmation_data: Some(SubjectConfirmationData {
                        not_before: None,
                        not_on_or_after: Some(now + Duration::minutes(5)),
                        recipient: Some(ACS_URL.to_string()),
                        in_response_to: Some(request_id.to_owned()),
                        address: None,
                        content: None,
                    }),
                }]),
            }),
            conditions: Some(Conditions {
                not_before: Some(now - Duration::minutes(1)),
                not_on_or_after: Some(now + Duration::minutes(5)),
                audience_restrictions: Some(vec![AudienceRestriction {
                    audience: vec![audience.to_string()],
                }]),
                one_time_use: None,
                proxy_restriction: None,
            }),
            authn_statements: Some(vec![AuthnStatement {
                authn_instant: Some(now),
                session_index: None,
                session_not_on_or_after: None,
                subject_locality: None,
                authn_context: Some(AuthnContext {
                    value: Some(AuthnContextClassRef {
                        value: Some("urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".to_string()),
                    }),
                }),
            }]),
            attribute_statements: Some(vec![samael::schema::AttributeStatement {
                attributes: attributes
                    .iter()
                    .map(|a| Attribute {
                        friendly_name: None,
                        name: Some(a.name.to_string()),
                        name_format: None,
                        values: vec![AttributeValue {
                            attribute_type: Some("xs:string".to_string()),
                            value: Some(a.value.to_string()),
                        }],
                    })
                    .collect(),
            }]),
        };
        let response_id = samael::crypto::gen_saml_response_id();
        let response = SchemaResponse {
            id: response_id.clone(),
            in_response_to: Some(request_id.to_owned()),
            version: "2.0".to_string(),
            issue_instant: now,
            destination: Some(ACS_URL.to_string()),
            consent: None,
            issuer: Some(issuer),
            signature: Some(samael::signature::Signature::template(&response_id, idp_cert_der)),
            status: Some(Status {
                status_code: StatusCode {
                    value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string()),
                },
                status_message: None,
                status_detail: None,
            }),
            encrypted_assertion: None,
            assertion: Some(assertion),
        };
        let unsigned_xml = response.to_string().unwrap();
        let private_key_der = if let Ok(rsa) = idp_private_key(idp) {
            rsa
        } else {
            panic!("clé privée IdP illisible")
        };
        let signed_xml = Crypto::sign_xml(unsigned_xml, &private_key_der).unwrap();
        SchemaResponse::from_str(&signed_xml).unwrap()
    }

    fn idp_private_key(idp: &TestIdp) -> Result<Vec<u8>, ()> {
        idp.export_private_key_der().map_err(|_| ())
    }

    const ACS_URL: &str = "https://sesame.example/auth/callback";
    const SP_ENTITY_ID: &str = "https://sesame.example/saml/metadata";
    const IDP_ENTITY_ID: &str = "https://idp.example/saml";

    /// Un IdP de test complet : clé + certificat, et le `Saml` du portail configuré pour lui
    /// faire confiance (mêmes valeurs que `SamlConfig` en configuration réelle).
    pub(crate) struct TestSetup {
        idp: TestIdp,
        idp_cert_der: samael::crypto::CertificateDer,
        pub(crate) saml: Saml,
    }

    pub(crate) fn setup() -> TestSetup {
        let idp = TestIdp::generate_new(KeyType::Rsa(Rsa::Rsa2048)).unwrap();
        let idp_cert_der = idp
            .create_certificate(&CertificateParams {
                common_name: "sesame-test-idp",
                issuer_name: "sesame-test-idp",
                days_until_expiration: 1,
            })
            .unwrap();
        let cert_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64_encode(idp_cert_der.der_data())
        );
        let cfg = SamlConfig {
            idp_entity_id: IDP_ENTITY_ID.to_string(),
            idp_sso_url: "https://idp.example/saml/sso".to_string(),
            idp_cert_pem: cert_pem,
            sp_entity_id: SP_ENTITY_ID.to_string(),
            user_key_attribute: None,
            email_attribute: Some("email".to_string()),
            groups_attribute: Some("groups".to_string()),
        };
        let saml = Saml::new(&cfg, ACS_URL.to_string()).unwrap();
        TestSetup {
            idp,
            idp_cert_der,
            saml,
        }
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn sign_response(
        setup: &TestSetup,
        name_id: &str,
        request_id: &str,
        audience: &str,
        attributes: &[TestAttribute],
    ) -> String {
        let response = build_and_sign_response(
            &setup.idp,
            &setup.idp_cert_der,
            name_id,
            request_id,
            audience,
            attributes,
        );
        base64_encode(response.to_string().unwrap().as_bytes())
    }

    fn pending(request_id: &str) -> PendingLogin {
        PendingLogin {
            csrf: "csrf-token".into(),
            return_to: "https://sesame.example/".into(),
            expires_at: u64::MAX,
            oidc: None,
            saml: Some(SamlPending {
                request_id: request_id.to_string(),
            }),
        }
    }

    fn email_attr(value: &str) -> TestAttribute<'_> {
        TestAttribute { name: "email", value }
    }

    #[test]
    fn accepts_a_correctly_signed_response_and_maps_attributes() {
        let setup = setup();
        let body = sign_response(
            &setup,
            "alice",
            "_req-1",
            SP_ENTITY_ID,
            &[email_attr("alice@example.org")],
        );
        let user = setup.saml.finish(&body, &pending("_req-1")).unwrap();
        assert_eq!(user.user_key, "alice");
        assert_eq!(user.issuer, IDP_ENTITY_ID);
        assert_eq!(user.display_name.as_deref(), Some("alice@example.org"));
    }

    #[test]
    fn rejects_a_response_signed_by_an_untrusted_key() {
        let setup = setup();
        let other_idp = TestIdp::generate_new(KeyType::Rsa(Rsa::Rsa2048)).unwrap();
        let other_cert = other_idp
            .create_certificate(&CertificateParams {
                common_name: "attacker",
                issuer_name: "attacker",
                days_until_expiration: 1,
            })
            .unwrap();
        let response = build_and_sign_response(&other_idp, &other_cert, "alice", "_req-1", SP_ENTITY_ID, &[]);
        let body = base64_encode(response.to_string().unwrap().as_bytes());
        assert!(setup.saml.finish(&body, &pending("_req-1")).is_err());
    }

    #[test]
    fn rejects_a_replayed_response_with_a_different_pending_request_id() {
        let setup = setup();
        let body = sign_response(&setup, "alice", "_req-1", SP_ENTITY_ID, &[]);
        // La réponse porte InResponseTo=_req-1, mais l'état conservé attend _req-2 : rejouer
        // une réponse valide sur une autre tentative de connexion doit échouer.
        assert!(setup.saml.finish(&body, &pending("_req-2")).is_err());
    }

    #[test]
    fn rejects_a_response_for_a_different_audience() {
        let setup = setup();
        let body = sign_response(&setup, "alice", "_req-1", "https://other-sp.example", &[]);
        assert!(setup.saml.finish(&body, &pending("_req-1")).is_err());
    }

    #[test]
    fn rejects_a_tampered_assertion() {
        let setup = setup();
        let body = sign_response(&setup, "alice", "_req-1", SP_ENTITY_ID, &[]);
        use base64::Engine;
        let mut xml =
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(&body).unwrap()).unwrap();
        xml = xml.replacen("alice", "mallory", 1);
        let tampered = base64_encode(xml.as_bytes());
        assert!(setup.saml.finish(&tampered, &pending("_req-1")).is_err());
    }

    #[test]
    fn builds_idp_metadata_from_pem_with_or_without_headers() {
        let cert = "MIIB+jCC...==";
        let pem = format!("-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----\n");
        assert_eq!(pem_body(&pem).unwrap(), cert);
        assert_eq!(pem_body(cert).unwrap(), cert);
        assert!(pem_body("").is_err());
    }

    #[test]
    fn sp_metadata_advertises_entity_id_and_acs_url() {
        let setup = setup();
        let xml = setup.saml.metadata_xml().unwrap();
        assert!(xml.contains(SP_ENTITY_ID));
        assert!(xml.contains(ACS_URL));
    }

    #[test]
    fn rejects_unsafe_user_key_from_name_id() {
        let setup = setup();
        let body = sign_response(&setup, "../admin", "_req-1", SP_ENTITY_ID, &[]);
        assert!(setup.saml.finish(&body, &pending("_req-1")).is_err());
    }
}
