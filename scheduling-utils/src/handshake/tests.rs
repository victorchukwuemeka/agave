use {
    crate::handshake::{
        client::{connect, ClientHandshakeError},
        server::{AgaveHandshakeError, Server},
        shared::MAX_WORKERS,
        ClientLogon,
    },
    agave_scheduler_bindings::{
        PackToWorkerMessage, ProgressMessage, SharableTransactionBatchRegion,
        SharableTransactionRegion, TpuToPackMessage, TransactionResponseRegion,
        WorkerToPackMessage,
    },
    std::time::Duration,
    tempfile::NamedTempFile,
};

#[test]
fn message_passing_on_all_queues() {
    let ipc = NamedTempFile::new().unwrap();
    std::fs::remove_file(ipc.path()).unwrap();
    let mut server = Server::new(ipc.path()).unwrap();

    // Test messages.
    let tpu_to_pack = TpuToPackMessage {
        transaction: SharableTransactionRegion {
            offset: 10,
            length: 5,
        },
        flags: 21,
        src_addr: [4; 16],
    };
    let progress_tracker = ProgressMessage {
        current_slot: 3,
        next_leader_slot: 12,
        remaining_cost_units: 12_000_000,
        current_slot_progress: 32,
    };
    let pack_to_worker = PackToWorkerMessage {
        flags: 123,
        max_execution_slot: 100,
        batch: SharableTransactionBatchRegion {
            num_transactions: 5,
            transactions_offset: 100,
        },
    };
    let worker_to_pack = WorkerToPackMessage {
        batch: SharableTransactionBatchRegion {
            num_transactions: 5,
            transactions_offset: 100,
        },
        processed: 0x01,
        responses: TransactionResponseRegion {
            tag: 3,
            num_transaction_responses: 2,
            transaction_responses_offset: 1,
        },
    };

    let server_handle = std::thread::spawn(move || {
        let mut session = server.accept().unwrap();

        // Send a tpu_to_pack message.
        let mut slot = session.tpu_to_pack.queue.reserve().unwrap();
        unsafe { *slot.as_mut() = tpu_to_pack };
        session.tpu_to_pack.queue.commit();

        // Send a progress_tracker message.
        let mut slot = session.progress_tracker.reserve().unwrap();
        unsafe { *slot.as_mut() = progress_tracker };
        session.progress_tracker.commit();

        // Receive pack_to_worker messages.
        for (i, worker) in session.workers.iter_mut().enumerate() {
            let msg = loop {
                worker.pack_to_worker.sync();
                if let Some(slot) = worker.pack_to_worker.try_read() {
                    break unsafe { *slot.as_ref() };
                }
            };
            assert_eq!(
                PackToWorkerMessage {
                    max_execution_slot: pack_to_worker.max_execution_slot + i as u64,
                    ..pack_to_worker
                },
                msg
            );
        }

        // Send worker_to_pack messages.
        for (i, worker) in session.workers.iter_mut().enumerate() {
            let mut slot = worker.worker_to_pack.reserve().unwrap();
            unsafe {
                *slot.as_mut() = WorkerToPackMessage {
                    batch: SharableTransactionBatchRegion {
                        num_transactions: worker_to_pack.batch.num_transactions + i as u8,
                        ..worker_to_pack.batch
                    },
                    ..worker_to_pack
                }
            };
            worker.worker_to_pack.commit();
        }
    });
    let client_handle = std::thread::spawn(move || {
        let mut session = connect(
            ipc,
            ClientLogon {
                worker_count: 4,
                allocator_size: 1024 * 1024 * 1024,
                allocator_handles: 3,
                tpu_to_pack_size: 65536 * 1024,
                progress_tracker_size: 16 * 1024,
                pack_to_worker_size: 1024 * 1024,
                worker_to_pack_size: 1024 * 1024,
            },
            Duration::from_secs(1),
        )
        .unwrap();

        // Receive tpu_to_pack message.
        let msg = loop {
            session.tpu_to_pack.sync();
            if let Some(msg) = session.tpu_to_pack.try_read() {
                break unsafe { *msg.as_ref() };
            };
        };
        assert_eq!(msg, tpu_to_pack);

        // Receive progress_tracker message.
        let msg = loop {
            session.progress_tracker.sync();
            if let Some(msg) = session.progress_tracker.try_read() {
                break unsafe { *msg.as_ref() };
            };
        };
        assert_eq!(msg, progress_tracker);

        // Send pack_to_worker messages.
        for (i, worker) in session.workers.iter_mut().enumerate() {
            let mut slot = worker.pack_to_worker.reserve().unwrap();
            unsafe {
                *slot.as_mut() = PackToWorkerMessage {
                    max_execution_slot: pack_to_worker.max_execution_slot + i as u64,
                    ..pack_to_worker
                }
            };
            worker.pack_to_worker.commit();
        }

        // Receive worker_to_pack messages.
        for (i, worker) in session.workers.iter_mut().enumerate() {
            let msg = loop {
                worker.worker_to_pack.sync();
                if let Some(slot) = worker.worker_to_pack.try_read() {
                    break unsafe { *slot.as_ref() };
                }
            };
            assert_eq!(
                WorkerToPackMessage {
                    batch: SharableTransactionBatchRegion {
                        num_transactions: worker_to_pack.batch.num_transactions + i as u8,
                        ..worker_to_pack.batch
                    },
                    ..worker_to_pack
                },
                msg
            );
        }
    });

    client_handle.join().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn accept_worker_count_max() {
    let ipc = NamedTempFile::new().unwrap();
    std::fs::remove_file(ipc.path()).unwrap();
    let mut server = Server::new(ipc.path()).unwrap();

    let server_handle = std::thread::spawn(move || {
        let res = server.accept();
        assert!(res.is_ok());
    });
    let client_handle = std::thread::spawn(move || {
        let res = connect(
            ipc,
            ClientLogon {
                worker_count: MAX_WORKERS,
                allocator_size: 1024 * 1024 * 1024,
                allocator_handles: 3,
                tpu_to_pack_size: 65536 * 1024,
                progress_tracker_size: 16 * 1024,
                pack_to_worker_size: 1024 * 1024,
                worker_to_pack_size: 1024 * 1024,
            },
            Duration::from_secs(1),
        );
        assert!(res.is_ok());
    });

    client_handle.join().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn reject_worker_count_low() {
    let ipc = NamedTempFile::new().unwrap();
    std::fs::remove_file(ipc.path()).unwrap();
    let mut server = Server::new(ipc.path()).unwrap();

    let server_handle = std::thread::spawn(move || {
        let res = server.accept();
        let Err(AgaveHandshakeError::WorkerCount(count)) = res else {
            panic!();
        };
        assert_eq!(count, 0);
    });
    let client_handle = std::thread::spawn(move || {
        let res = connect(
            ipc,
            ClientLogon {
                worker_count: 0,
                allocator_size: 1024 * 1024 * 1024,
                allocator_handles: 3,
                tpu_to_pack_size: 65536 * 1024,
                progress_tracker_size: 16 * 1024,
                pack_to_worker_size: 1024 * 1024,
                worker_to_pack_size: 1024 * 1024,
            },
            Duration::from_secs(1),
        );
        let Err(ClientHandshakeError::Rejected(reason)) = res else {
            panic!();
        };
        assert_eq!(reason, "Worker count; count=0");
    });

    client_handle.join().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn reject_worker_count_high() {
    let ipc = NamedTempFile::new().unwrap();
    std::fs::remove_file(ipc.path()).unwrap();
    let mut server = Server::new(ipc.path()).unwrap();

    let server_handle = std::thread::spawn(move || {
        let res = server.accept();
        let Err(AgaveHandshakeError::WorkerCount(count)) = res else {
            panic!();
        };
        assert_eq!(count, 100);
    });
    let client_handle = std::thread::spawn(move || {
        let res = connect(
            ipc,
            ClientLogon {
                worker_count: 100,
                allocator_size: 1024 * 1024 * 1024,
                allocator_handles: 3,
                tpu_to_pack_size: 65536 * 1024,
                progress_tracker_size: 16 * 1024,
                pack_to_worker_size: 1024 * 1024,
                worker_to_pack_size: 1024 * 1024,
            },
            Duration::from_secs(1),
        );
        let Err(ClientHandshakeError::Rejected(reason)) = res else {
            panic!();
        };
        assert_eq!(reason, "Worker count; count=100");
    });

    client_handle.join().unwrap();
    server_handle.join().unwrap();
}

#[test]
fn reject_invalid_queue_size() {
    let ipc = NamedTempFile::new().unwrap();
    std::fs::remove_file(ipc.path()).unwrap();
    let mut server = Server::new(ipc.path()).unwrap();

    let server_handle = std::thread::spawn(move || {
        let res = server.accept();
        assert!(matches!(res, Err(AgaveHandshakeError::Shaq(_))));
    });
    let client_handle = std::thread::spawn(move || {
        let res = connect(
            ipc,
            ClientLogon {
                worker_count: 4,
                allocator_size: 1024 * 1024 * 1024,
                allocator_handles: 3,
                tpu_to_pack_size: 0,
                progress_tracker_size: 16 * 1024,
                pack_to_worker_size: 1024 * 1024,
                worker_to_pack_size: 1024 * 1024,
            },
            Duration::from_secs(1),
        );
        let Err(ClientHandshakeError::Rejected(reason)) = res else {
            panic!();
        };
        assert_eq!(reason, "Shaq; err=InvalidBufferSize");
    });

    client_handle.join().unwrap();
    server_handle.join().unwrap();
}
