use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const CONTAINERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("containers");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerState {
    pub slot: usize,
    pub started_at: u64, // unix timestamp
    #[serde(default)]
    pub busy_since: Option<u64>, // unix timestamp, set only while GitHub reports busy
}

impl ContainerState {
    pub fn new(slot: usize) -> Self {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Self {
            slot,
            started_at,
            busy_since: None,
        }
    }

    /// Returns how long this container has been running in seconds
    pub fn running_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        now.saturating_sub(self.started_at)
    }

    fn now_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }

    /// Mark this runner as busy, preserving the first observed busy timestamp.
    pub fn mark_busy(&mut self) {
        if self.busy_since.is_none() {
            self.busy_since = Some(Self::now_seconds());
        }
    }

    /// Mark this runner as idle.
    pub fn mark_idle(&mut self) {
        self.busy_since = None;
    }

    /// Returns how long this runner has been observed as busy.
    pub fn busy_seconds(&self) -> Option<u64> {
        self.busy_since
            .map(|busy_since| Self::now_seconds().saturating_sub(busy_since))
    }
}

pub struct StateDb {
    db: Database,
}

impl StateDb {
    /// Open or create the state database
    pub fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("Failed to create state directory: {:?}", state_dir))?;

        let db_path = state_dir.join("state.redb");
        let db = Database::create(&db_path)
            .with_context(|| format!("Failed to open database: {:?}", db_path))?;

        // Ensure table exists
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(CONTAINERS_TABLE)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Insert or update a container state
    pub fn put_container(&self, name: &str, state: &ContainerState) -> Result<()> {
        let data = serde_json::to_vec(state)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CONTAINERS_TABLE)?;
            table.insert(name, data.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a container state by name
    pub fn get_container(&self, name: &str) -> Result<Option<ContainerState>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CONTAINERS_TABLE)?;

        match table.get(name)? {
            Some(data) => {
                let state: ContainerState = serde_json::from_slice(data.value())?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    /// Remove a container state
    pub fn remove_container(&self, name: &str) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CONTAINERS_TABLE)?;
            table.remove(name)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all container states
    pub fn list_containers(&self) -> Result<Vec<(String, ContainerState)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(CONTAINERS_TABLE)?;

        let mut containers = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let name = key.value().to_string();
            let state: ContainerState = serde_json::from_slice(value.value())?;
            containers.push((name, state));
        }

        Ok(containers)
    }

    /// Clear all container states (used by explicit destructive cleanup paths)
    pub fn clear_all(&self) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(CONTAINERS_TABLE)?;
            // Collect keys first to avoid borrowing issues
            let keys: Vec<String> = table
                .iter()?
                .filter_map(|e| e.ok().map(|(k, _)| k.value().to_string()))
                .collect();

            for key in keys {
                table.remove(key.as_str())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}
