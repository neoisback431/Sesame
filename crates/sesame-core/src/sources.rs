// SPDX-License-Identifier: Apache-2.0
//! Catalogue des applis : descripteurs en fichiers (Git, lecture seule) et en base
//! (créés dans l'UI d'administration), fusionnés.
//!
//! Les fichiers sont chargés au démarrage : un fichier invalide empêche le démarrage.
//! Les descripteurs en base sont relus à chaud : un document invalide, ou dont
//! l'identifiant ou l'hôte public est déjà pris, est écarté et signalé, sans
//! interrompre le service.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use crate::descriptor::{load_dir, AppDescriptor, DescriptorError};
use crate::ports::{DescriptorStore, PortResult};

pub struct DescriptorSource {
    files: Vec<AppDescriptor>,
    store: Option<Arc<dyn DescriptorStore>>,
}

/// Résultat d'un chargement : applis retenues et descripteurs écartés (raison lisible).
pub struct Catalog {
    pub descriptors: Vec<AppDescriptor>,
    pub rejected: Vec<String>,
}

impl DescriptorSource {
    /// `dir` absent ou inexistant : aucun descripteur en fichier.
    pub fn new(
        dir: Option<PathBuf>,
        store: Option<Arc<dyn DescriptorStore>>,
    ) -> Result<Self, DescriptorError> {
        let files = match dir {
            Some(d) if d.is_dir() => load_dir(&d)?,
            _ => Vec::new(),
        };
        Ok(Self { files, store })
    }

    pub fn from_parts(files: Vec<AppDescriptor>, store: Option<Arc<dyn DescriptorStore>>) -> Self {
        Self { files, store }
    }

    /// Version du catalogue en base (0 sans base) : le rechargement n'a lieu que si elle change.
    pub async fn version(&self) -> PortResult<i64> {
        match &self.store {
            Some(s) => s.version().await,
            None => Ok(0),
        }
    }

    pub async fn load(&self) -> PortResult<Catalog> {
        let mut descriptors = self.files.clone();
        let mut rejected = Vec::new();
        let mut ids: HashSet<String> = descriptors.iter().map(|d| d.metadata.id.clone()).collect();
        let mut hosts: HashSet<String> = descriptors.iter().map(|d| d.spec.public.host.clone()).collect();
        if let Some(store) = &self.store {
            for stored in store.list_descriptors().await? {
                let d = match AppDescriptor::from_json(stored.document) {
                    Ok(d) => d,
                    Err(e) => {
                        rejected.push(format!("{} : {e}", stored.app_id));
                        continue;
                    }
                };
                if d.metadata.id != stored.app_id {
                    rejected.push(format!("{} : metadata.id différent de la clé", stored.app_id));
                } else if ids.contains(&d.metadata.id) {
                    rejected.push(format!("{} : identifiant déjà utilisé", stored.app_id));
                } else if hosts.contains(&d.spec.public.host) {
                    rejected.push(format!("{} : hôte public déjà utilisé", stored.app_id));
                } else {
                    ids.insert(d.metadata.id.clone());
                    hosts.insert(d.spec.public.host.clone());
                    descriptors.push(d);
                }
            }
        }
        Ok(Catalog {
            descriptors,
            rejected,
        })
    }
}

/// Boucle de rechargement à chaud : à chaque intervalle, si la version du catalogue
/// en base a changé depuis `initial_version`, recharge et appelle `apply`.
/// Une erreur de lecture est journalisée et la boucle continue.
pub async fn watch<F>(
    source: Arc<DescriptorSource>,
    interval: std::time::Duration,
    initial_version: i64,
    mut apply: F,
) where
    F: FnMut(Catalog) + Send,
{
    let mut last = initial_version;
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // le premier tic est immédiat : le catalogue initial est déjà chargé
    loop {
        tick.tick().await;
        let version = match source.version().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "version du catalogue illisible");
                continue;
            }
        };
        if version == last {
            continue;
        }
        match source.load().await {
            Ok(catalog) => {
                last = version;
                apply(catalog);
            }
            Err(e) => tracing::warn!(error = %e, "rechargement du catalogue impossible"),
        }
    }
}

/// Journalise les descripteurs écartés d'un catalogue.
pub fn log_rejected(catalog: &Catalog) {
    for reason in &catalog.rejected {
        tracing::error!(reason = %reason, "descripteur écarté");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryDescriptorStore;

    const FAKE_APP: &str = include_str!("../../../descriptors/fake-app.yaml");

    fn doc(id: &str, host: &str) -> serde_json::Value {
        let mut v: serde_json::Value = serde_yaml::from_str(FAKE_APP).unwrap();
        v["metadata"]["id"] = id.into();
        v["spec"]["public"]["host"] = host.into();
        v
    }

    #[tokio::test]
    async fn merges_files_and_database() {
        let store = Arc::new(MemoryDescriptorStore::default());
        let files = vec![AppDescriptor::from_yaml(FAKE_APP).unwrap()];
        let source = DescriptorSource::from_parts(files, Some(store.clone()));
        assert_eq!(source.version().await.unwrap(), 0);

        store
            .put_descriptor("crm", doc("crm", "crm.test"), Some("admin"))
            .await
            .unwrap();
        store
            .put_descriptor("fake-app", doc("fake-app", "x.test"), None)
            .await
            .unwrap();
        store
            .put_descriptor("dup-host", doc("dup-host", "crm.test"), None)
            .await
            .unwrap();
        let mut broken = doc("broken", "b.test");
        broken["spec"]["login"]["fields"]["password"] = serde_json::json!({"from_secret": "pin"});
        store.put_descriptor("broken", broken, None).await.unwrap();
        store
            .put_descriptor("mismatch", doc("autre", "m.test"), None)
            .await
            .unwrap();

        let catalog = source.load().await.unwrap();
        let ids: Vec<_> = catalog
            .descriptors
            .iter()
            .map(|d| d.metadata.id.as_str())
            .collect();
        assert_eq!(ids, ["fake-app", "crm"]);
        assert_eq!(catalog.rejected.len(), 4, "{:?}", catalog.rejected);
        assert!(source.version().await.unwrap() > 0);
    }

    #[tokio::test(start_paused = true)]
    async fn watch_reloads_only_on_change() {
        let store = Arc::new(MemoryDescriptorStore::default());
        let source = Arc::new(DescriptorSource::from_parts(Vec::new(), Some(store.clone())));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let v0 = source.version().await.unwrap();
        tokio::spawn(watch(
            source,
            std::time::Duration::from_secs(5),
            v0,
            move |c: Catalog| {
                let _ = tx.send(c.descriptors.len());
            },
        ));
        tokio::time::sleep(std::time::Duration::from_secs(12)).await;
        assert!(rx.try_recv().is_err(), "pas de changement, pas de rechargement");
        store
            .put_descriptor("crm", doc("crm", "crm.test"), None)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
        assert_eq!(rx.recv().await, Some(1));
    }

    #[tokio::test]
    async fn missing_directory_means_no_files() {
        let source = DescriptorSource::new(Some("/nonexistent".into()), None).unwrap();
        assert!(source.load().await.unwrap().descriptors.is_empty());
    }
}
