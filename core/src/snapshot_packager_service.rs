mod snapshot_gossip_manager;
use {
    agave_snapshots::{snapshot_config::SnapshotConfig, snapshot_hash::StartingSnapshotHashes},
    snapshot_gossip_manager::SnapshotGossipManager,
    solana_accounts_db::accounts_db::AccountStorageEntry,
    solana_clock::Slot,
    solana_gossip::cluster_info::ClusterInfo,
    solana_measure::{meas_dur, measure::Measure, measure_us},
    solana_perf::thread::renice_this_thread,
    solana_runtime::{
        accounts_background_service::PendingSnapshotPackages,
        snapshot_controller::SnapshotController, snapshot_package::SnapshotPackage, snapshot_utils,
    },
    std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread::{self, Builder, JoinHandle},
        time::{Duration, Instant},
    },
};

pub struct SnapshotPackagerService {
    t_snapshot_packager: JoinHandle<()>,
}

impl SnapshotPackagerService {
    pub const NAME: &str = "SnapshotPackagerService";

    /// If there are no snapshot packages to handle, limit how often we re-check
    const LOOP_LIMITER: Duration = Duration::from_millis(100);

    pub fn new(
        pending_snapshot_packages: Arc<Mutex<PendingSnapshotPackages>>,
        starting_snapshot_hashes: Option<StartingSnapshotHashes>,
        exit: Arc<AtomicBool>,
        exit_backpressure: Option<Arc<AtomicBool>>,
        cluster_info: Arc<ClusterInfo>,
        snapshot_controller: Arc<SnapshotController>,
        enable_gossip_push: bool,
    ) -> Self {
        let t_snapshot_packager = Builder::new()
            .name("solSnapshotPkgr".to_string())
            .spawn(move || {
                if let Some(exit_backpressure) = &exit_backpressure {
                    exit_backpressure.store(true, Ordering::Relaxed);
                }
                info!("{} has started", Self::NAME);
                let snapshot_config = snapshot_controller.snapshot_config();
                renice_this_thread(snapshot_config.packager_thread_niceness_adj).unwrap();
                let mut snapshot_gossip_manager = enable_gossip_push
                    .then(|| SnapshotGossipManager::new(cluster_info, starting_snapshot_hashes));

                let mut teardown_state = None;
                loop {
                    if exit.load(Ordering::Relaxed) {
                        if let Some(teardown_state) = &teardown_state {
                            info!("Received exit request, tearing down...");
                            let (_, dur) = meas_dur!(Self::teardown(
                                teardown_state,
                                snapshot_controller.snapshot_config(),
                            ));
                            info!("Teardown completed in {dur:?}.");
                        }
                        break;
                    }

                    let Some(snapshot_package) =
                        Self::get_next_snapshot_package(&pending_snapshot_packages)
                    else {
                        std::thread::sleep(Self::LOOP_LIMITER);
                        continue;
                    };
                    info!("handling snapshot package: {snapshot_package:?}");
                    let enqueued_time = snapshot_package.enqueued.elapsed();

                    let measure_handling = Measure::start("");
                    let snapshot_kind = snapshot_package.snapshot_kind;
                    let snapshot_slot = snapshot_package.slot;
                    let snapshot_hash = snapshot_package.hash;

                    if exit_backpressure.is_some() {
                        // With exit backpressure, we will delay flushing snapshot storages
                        // until we receive a graceful exit request.
                        // Save the snapshot storages here, so we can flush later (as needed).
                        teardown_state = Some(TeardownState {
                            snapshot_slot: snapshot_package.slot,
                            snapshot_storages: snapshot_package.snapshot_storages.clone(),
                        });
                    }

                    // Archiving the snapshot package is not allowed to fail.
                    // AccountsBackgroundService calls `clean_accounts()` with a value for
                    // latest_full_snapshot_slot that requires this archive call to succeed.
                    let (archive_result, archive_time_us) =
                        measure_us!(snapshot_utils::serialize_and_archive_snapshot_package(
                            snapshot_package,
                            snapshot_config,
                            // Without exit backpressure, always flush the snapshot storages,
                            // which is required for fastboot.
                            exit_backpressure.is_none(),
                        ));
                    if let Err(err) = archive_result {
                        error!(
                            "Stopping {}! Fatal error while archiving snapshot package: {err}",
                            Self::NAME,
                        );
                        exit.store(true, Ordering::Relaxed);
                        break;
                    }

                    if let Some(snapshot_gossip_manager) = snapshot_gossip_manager.as_mut() {
                        snapshot_gossip_manager
                            .push_snapshot_hash(snapshot_kind, (snapshot_slot, snapshot_hash));
                    }

                    let (_, purge_archives_time_us) =
                        measure_us!(snapshot_utils::purge_old_snapshot_archives(
                            &snapshot_config.full_snapshot_archives_dir,
                            &snapshot_config.incremental_snapshot_archives_dir,
                            snapshot_config.maximum_full_snapshot_archives_to_retain,
                            snapshot_config.maximum_incremental_snapshot_archives_to_retain,
                        ));

                    // Now that this snapshot package has been archived, it is safe to remove
                    // all bank snapshots older than this slot.  We want to keep the bank
                    // snapshot *at this slot* so that it can be used during restarts, when
                    // booting from local state.
                    let (_, purge_bank_snapshots_time_us) =
                        measure_us!(snapshot_utils::purge_bank_snapshots_older_than_slot(
                            &snapshot_config.bank_snapshots_dir,
                            snapshot_slot,
                        ));

                    let handling_time_us = measure_handling.end_as_us();
                    datapoint_info!(
                        "snapshot_packager_service",
                        ("enqueued_time_us", enqueued_time.as_micros(), i64),
                        ("handling_time_us", handling_time_us, i64),
                        ("archive_time_us", archive_time_us, i64),
                        (
                            "purge_old_snapshots_time_us",
                            purge_bank_snapshots_time_us,
                            i64
                        ),
                        ("purge_old_archives_time_us", purge_archives_time_us, i64),
                    );
                }
                info!("{} has stopped", Self::NAME);
                if let Some(exit_backpressure) = &exit_backpressure {
                    exit_backpressure.store(false, Ordering::Relaxed);
                }
            })
            .unwrap();

        Self {
            t_snapshot_packager,
        }
    }

    pub fn join(self) -> thread::Result<()> {
        self.t_snapshot_packager.join()
    }

    /// Returns the next snapshot package to handle
    fn get_next_snapshot_package(
        pending_snapshot_packages: &Mutex<PendingSnapshotPackages>,
    ) -> Option<SnapshotPackage> {
        pending_snapshot_packages.lock().unwrap().pop()
    }

    /// Performs final operations before gracefully shutting down
    fn teardown(state: &TeardownState, snapshot_config: &SnapshotConfig) {
        info!("Flushing account storages...");
        let start = Instant::now();
        for storage in &state.snapshot_storages {
            let result = storage.flush();
            if let Err(err) = result {
                warn!(
                    "Failed to flush account storage '{}': {err}",
                    storage.path().display(),
                );
                // If flushing a storage failed, we do *NOT* want to write
                // the "storages flushed" file, so return early.
                return;
            }
        }
        info!("Flushing account storages... Done in {:?}", start.elapsed());

        let bank_snapshot_dir = snapshot_utils::get_bank_snapshot_dir(
            &snapshot_config.bank_snapshots_dir,
            state.snapshot_slot,
        );

        info!("Hard linking account storages...");
        let start = Instant::now();
        let result = snapshot_utils::hard_link_storages_to_snapshot(
            &bank_snapshot_dir,
            state.snapshot_slot,
            &state.snapshot_storages,
        );
        if let Err(err) = result {
            warn!("Failed to hard link account storages: {err}");
            // If hard linking the storages failed, we do *NOT* want to mark the bank snapshot as
            // loadable so return early.
            return;
        }
        info!(
            "Hard linking account storages... Done in {:?}",
            start.elapsed(),
        );

        info!("Saving obsolete accounts...");
        let start = Instant::now();
        let result = snapshot_utils::write_obsolete_accounts_to_snapshot(
            &bank_snapshot_dir,
            &state.snapshot_storages,
            state.snapshot_slot,
        );
        if let Err(err) = result {
            warn!("Failed to serialize obsolete accounts: {err}");
            // If serializing the obsolete accounts failed, we do *NOT* want to mark the bank snapshot
            // as loadable so return early.
            return;
        }
        info!("Saving obsolete accounts... Done in {:?}", start.elapsed());

        let result = snapshot_utils::mark_bank_snapshot_as_loadable(&bank_snapshot_dir);
        if let Err(err) = result {
            warn!("Failed to mark bank snapshot as loadable: {err}");
        }
    }
}

/// The state required to run `teardown()`
// Note, don't derive Debug, because we don't want to print out 432k+ `AccountStorageEntry`s...
struct TeardownState {
    /// The slot of the latest snapshot
    snapshot_slot: Slot,
    /// The storages of the latest snapshot
    snapshot_storages: Vec<Arc<AccountStorageEntry>>,
}
