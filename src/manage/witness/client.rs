//! Explicit offline source-side witness operations. This is a diagnostic and
//! reconciliation entry point, not automatic source commit protection. The
//! caller retains enrollment/transition files; no failure creates a new intent.

use super::{Enrollment, Error, Record, Transition};
use crate::manage::{
    node::control::{
        Offline,
        witness::{Action, Operation},
    },
    store, tls,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Private keys are file inputs, never CLI secrets. Source serve must be
/// stopped: the existing process-author lock excludes identity/recovery changes
/// while loading TLS and performing this one bounded remote operation.
#[derive(clap::Args)]
pub struct Args {
    /// Existing offline source management directory (schema 25 or later)
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Canonical HTTPS origin of the already registered witness peer
    #[arg(long)]
    endpoint: String,
    /// Retained Enrollment JSON; all fields must match the witness record
    #[arg(long)]
    enrollment: PathBuf,
    /// Explicit PEM roots for the node trust domain
    #[arg(long)]
    ca: PathBuf,
    /// Local node leaf/chain PEM, registered by the witness operator
    #[arg(long)]
    cert: PathBuf,
    /// Private PEM key matching the local node leaf
    #[arg(long)]
    key: PathBuf,
    #[command(subcommand)]
    action: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Read the exact retained binding without advancing or confirming it
    Inspect,
    /// Reserve the original transition; does not commit anything on the source
    Reserve {
        /// Retained Transition JSON; keep it unchanged after an uncertain reply
        #[arg(long)]
        input: PathBuf,
    },
    /// Acknowledge an original transition only after its source commit is known
    Confirm {
        /// The same Transition JSON used for reserve
        #[arg(long)]
        input: PathBuf,
    },
}

fn transition(path: &Path) -> io::Result<Transition> {
    let bytes = crate::manage::files::read(path, 4096, false)?;
    let input: Transition = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid.error())?;
    input.validate()?;
    Ok(input)
}

/// Startup/recovery/key checks precede any network request. The ordinary node
/// client checks exact witness DER/SAN/revision both before HTTP and after the
/// response. A mutation error can leave a durable Pending/Confirmed record;
/// report uncertainty, never retry automatically or infer rollback from I/O.
pub(super) fn run(args: Args) -> io::Result<Record> {
    let bytes = crate::manage::files::read(&args.enrollment, 4096, false)?;
    let enrollment: Enrollment =
        serde_json::from_slice(&bytes).map_err(|_| Error::Invalid.error())?;
    enrollment.validate()?;
    let action = match args.action {
        Command::Inspect => Action::Inspect,
        Command::Reserve { input } => Action::Reserve(transition(&input)?),
        Command::Confirm { input } => Action::Confirm(transition(&input)?),
    };
    let mutation = !matches!(action, Action::Inspect);
    let expected = enrollment.witness_node_id.clone();
    let operation = Operation { enrollment, action };
    operation.validate(&expected)?;
    let directory = crate::manage::directory(args.data_dir)?;
    let author = Arc::new(store::lock(&directory)?);
    // Protected sources must reconcile through the original private intent;
    // the raw diagnostic CLI cannot bypass the SQL floor/commit gate.
    if mutation {
        store::recovery::startup(&directory)?;
    }
    let identity = tls::node_identity(&args.ca, &args.cert, &args.key)?;
    let source = Offline::new(
        &directory,
        author,
        &operation.enrollment.peer_node_id,
        identity,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    let result = runtime.block_on(source.request(&args.endpoint, &expected, operation));
    runtime.shutdown_timeout(Duration::from_secs(5));
    let fetched = result.map_err(|error| {
        if mutation {
            io::Error::new(error.kind(), format!(
                "witness result may be unknown; inspect the original binding before any exact retry: {error}"
            ))
        } else {
            error
        }
    })?;
    Ok(fetched.value)
}

#[cfg(test)]
mod tests {
    //! Exercise the real CLI execution path (not clap parsing) and production node
    //! router/client with fresh loopback identities; no browser/system trust is used.
    use super::*;
    use crate::manage::{node, policy::Coordinator, witness::Phase};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    async fn execute(args: Args) -> io::Result<Record> {
        tokio::task::spawn_blocking(move || run(args))
            .await
            .map_err(io::Error::other)?
    }

    #[test]
    fn protected_source_refuses_raw_witness_mutations_before_loading_tls_or_sending_http()
    -> io::Result<()> {
        let f = node::tests::Fixture::new(true, true)?;
        let e = Enrollment {
            witness_node_id: f.server_id.clone(),
            peer_node_id: f.client_id.clone(),
            binding_id: URL_SAFE_NO_PAD.encode([54_u8; 16]),
            writer_id: URL_SAFE_NO_PAD.encode([55_u8; 16]),
            baseline: "0".repeat(64),
        };
        let enrollment = f.write(
            "guard-enrollment.json",
            &serde_json::to_vec(&e).map_err(io::Error::other)?,
        )?;
        let input = Transition {
            witness_node_id: e.witness_node_id.clone(),
            binding_id: e.binding_id.clone(),
            writer_id: e.writer_id.clone(),
            sequence: "1".into(),
            previous: e.baseline.clone(),
            commitment: "1".repeat(64),
        };
        let input = f.write(
            "guard-transition.json",
            &serde_json::to_vec(&input).map_err(io::Error::other)?,
        )?;
        crate::manage::files::create_directory(&f.client_state.join("witness-source.json"))?;
        for confirm in [false, true] {
            let missing = f.client_state.join("unused-identity.pem");
            let args = Args {
                data_dir: Some(f.client_state.clone()),
                endpoint: "https://localhost:9".into(),
                enrollment: enrollment.clone(),
                ca: missing.clone(),
                cert: missing.clone(),
                key: missing,
                action: if confirm {
                    Command::Confirm {
                        input: input.clone(),
                    }
                } else {
                    Command::Reserve {
                        input: input.clone(),
                    }
                },
            };
            assert_eq!(
                run(args).err().map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
        }
        assert!(f.client_state.join("witness-source.json").is_dir());
        Ok(())
    }

    #[tokio::test]
    async fn witness_lost_cli_reply_is_unknown_and_reconciles_without_a_new_sequence()
    -> io::Result<()> {
        use std::sync::atomic::Ordering;
        let f = node::tests::Fixture::new(true, true)?;
        let enrollment = Enrollment {
            witness_node_id: f.server_id.clone(),
            binding_id: URL_SAFE_NO_PAD.encode([12_u8; 16]),
            peer_node_id: f.client_id.clone(),
            writer_id: URL_SAFE_NO_PAD.encode([13_u8; 16]),
            baseline: "0".repeat(64),
        };
        store::witness::bind(&f.server_state, &enrollment)?;
        let enrollment_file = f.write(
            "enrollment.json",
            &serde_json::to_vec(&enrollment).map_err(io::Error::other)?,
        )?;
        let input = Transition {
            witness_node_id: enrollment.witness_node_id.clone(),
            binding_id: enrollment.binding_id.clone(),
            writer_id: enrollment.writer_id.clone(),
            sequence: "1".into(),
            previous: enrollment.baseline.clone(),
            commitment: "1".repeat(64),
        };
        let input_file = f.write(
            "transition.json",
            &serde_json::to_vec(&input).map_err(io::Error::other)?,
        )?;
        let policy = Coordinator::new(
            f.server_state.clone(),
            store::load_policy(&f.server_state)?,
            Arc::new(store::lock(&f.server_state)?),
        )?;
        let fault = Arc::new(node::tests::CutResponse {
            witness_reserve: true,
            ..Default::default()
        });
        fault.armed.store(true, Ordering::Release);
        let stop = CancellationToken::new();
        let (address, task) =
            node::tests::start_cut_response_node(&f, policy, fault.clone(), stop.clone()).await?;
        let args = |action| Args {
            data_dir: Some(f.client_state.clone()),
            endpoint: format!("https://localhost:{}", address.port()),
            enrollment: enrollment_file.clone(),
            ca: f.ca.clone(),
            cert: f.client_cert.clone(),
            key: f.client_key.clone(),
            action,
        };
        let result = tokio::time::timeout(Duration::from_secs(20), async {
            let error = execute(args(Command::Reserve {
                input: input_file.clone(),
            }))
            .await
            .err()
            .ok_or_else(|| io::Error::other("truncated response accepted"))?;
            assert!(error.to_string().contains("may be unknown"));
            assert_eq!(fault.cuts.load(Ordering::Acquire), 1);
            let pending = execute(args(Command::Inspect)).await?;
            assert_eq!(pending.phase, Phase::Pending);
            assert_eq!(pending.sequence, input.sequence);
            assert_eq!(pending.previous.as_ref(), Some(&input.previous));
            assert_eq!(pending.commitment, input.commitment);
            assert_eq!(
                store::witness::inspect(&f.server_state, &enrollment.binding_id)?,
                pending
            );
            // Explicit exact retry is idempotent; neither the failed call nor the
            // read invents a replacement sequence or auto-confirms the reservation.
            assert_eq!(
                execute(args(Command::Reserve {
                    input: input_file.clone()
                }))
                .await?,
                pending
            );
            assert_eq!(fault.cuts.load(Ordering::Acquire), 1);
            Ok::<_, io::Error>(())
        })
        .await;
        stop.cancel();
        task.await.map_err(io::Error::other)??;
        result.map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "witness lost reply fixture deadline",
            )
        })?
    }

    #[tokio::test]
    async fn witness_remote_cli_retains_pending_and_exact_operation_without_proxy_ownership()
    -> io::Result<()> {
        let f = node::tests::Fixture::new(true, true)?;
        // Witness reconciliation precedes policy/meter restoration. A broken meter
        // catalog must remain an error for restore without preventing this separate
        // identity-bound diagnostic. Nothing here repairs or starts the source.
        {
            let connection = rusqlite::Connection::open(f.client_state.join("management.sqlite3"))
                .map_err(io::Error::other)?;
            connection
                .execute(
                    "UPDATE traffic_state SET series_count=1 WHERE singleton=1",
                    [],
                )
                .map_err(io::Error::other)?;
        }
        assert!(store::traffic::restore(&f.client_state).is_err());
        let enrollment = Enrollment {
            witness_node_id: f.server_id.clone(),
            binding_id: URL_SAFE_NO_PAD.encode([9_u8; 16]),
            peer_node_id: f.client_id.clone(),
            writer_id: URL_SAFE_NO_PAD.encode([10_u8; 16]),
            baseline: "0".repeat(64),
        };
        let baseline = store::witness::bind(&f.server_state, &enrollment)?;
        let enrollment_file = f.write(
            "enrollment.json",
            &serde_json::to_vec(&enrollment).map_err(io::Error::other)?,
        )?;
        let input = Transition {
            witness_node_id: enrollment.witness_node_id.clone(),
            binding_id: enrollment.binding_id.clone(),
            writer_id: enrollment.writer_id.clone(),
            sequence: "1".into(),
            previous: enrollment.baseline.clone(),
            commitment: "1".repeat(64),
        };
        let input_file = f.write(
            "transition.json",
            &serde_json::to_vec(&input).map_err(io::Error::other)?,
        )?;
        let mut changed = input.clone();
        changed.commitment = "2".repeat(64);
        let changed_file = f.write(
            "changed.json",
            &serde_json::to_vec(&changed).map_err(io::Error::other)?,
        )?;
        let policy = Coordinator::new(
            f.server_state.clone(),
            store::load_policy(&f.server_state)?,
            Arc::new(store::lock(&f.server_state)?),
        )?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let stop = CancellationToken::new();
        let task = tokio::spawn(node::serve(
            listener,
            f.config(address)?,
            f.server_state.clone(),
            stop.clone(),
            Some(policy.clone()),
            None,
            None,
        ));
        let args = |action| Args {
            data_dir: Some(f.client_state.clone()),
            endpoint: format!("https://localhost:{}", address.port()),
            enrollment: enrollment_file.clone(),
            ca: f.ca.clone(),
            cert: f.client_cert.clone(),
            key: f.client_key.clone(),
            action,
        };
        let result = tokio::time::timeout(Duration::from_secs(25), async {
            assert_eq!(execute(args(Command::Inspect)).await?, baseline);
            // Discard the first response, then reconcile with a read, not a new
            // writer/sequence. Each call creates a fresh real TLS connection.
            assert_eq!(
                execute(args(Command::Reserve {
                    input: input_file.clone()
                }))
                .await?
                .phase,
                Phase::Pending
            );
            let pending = execute(args(Command::Inspect)).await?;
            assert_eq!(pending.sequence, "1");
            assert_eq!(pending.phase, Phase::Pending);
            let error = execute(args(Command::Reserve {
                input: changed_file,
            }))
            .await
            .err()
            .ok_or_else(|| io::Error::other("changed payload accepted"))?;
            assert!(error.to_string().contains("may be unknown"));
            assert_eq!(execute(args(Command::Inspect)).await?, pending);
            assert_eq!(
                execute(args(Command::Reserve {
                    input: input_file.clone()
                }))
                .await?,
                pending
            );
            let confirmed = execute(args(Command::Confirm {
                input: input_file.clone(),
            }))
            .await?;
            assert_eq!(confirmed.phase, Phase::Confirmed);
            assert_eq!(
                execute(args(Command::Reserve {
                    input: input_file.clone()
                }))
                .await?,
                confirmed
            );
            assert_eq!(
                execute(args(Command::Confirm {
                    input: input_file.clone()
                }))
                .await?,
                confirmed
            );
            // Both local and remote source identities are fixed. A foreign
            // enrollment is denied before even attempting this invalid origin.
            let mut wrong = enrollment.clone();
            wrong.peer_node_id = URL_SAFE_NO_PAD.encode([11_u8; 16]);
            let wrong_file = f.write(
                "wrong-source.json",
                &serde_json::to_vec(&wrong).map_err(io::Error::other)?,
            )?;
            let mut wrong_args = args(Command::Inspect);
            wrong_args.enrollment = wrong_file;
            wrong_args.endpoint = "not-an-origin".into();
            assert_eq!(
                execute(wrong_args).await.err().map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            let id = f.client_id.clone();
            policy
                .metadata_write(move |directory| store::set_peer_active(directory, &id, 1, false))
                .await?;
            let denied = execute(args(Command::Inspect))
                .await
                .err()
                .ok_or_else(|| io::Error::other("revoked source accepted"))?;
            assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(
                store::witness::inspect(&f.server_state, &enrollment.binding_id)?,
                confirmed
            );
            // Revoking the local witness registration cannot be replaced by a valid
            // CA chain or the previously successful remote application response.
            store::set_peer_active(&f.client_state, &f.server_id, 1, false)?;
            assert_eq!(
                execute(args(Command::Inspect))
                    .await
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
            assert!(store::traffic::restore(&f.client_state).is_err());
            Ok::<_, io::Error>(())
        })
        .await;
        stop.cancel();
        task.await.map_err(io::Error::other)??;
        result.map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "witness client fixture deadline")
        })?
    }
}
