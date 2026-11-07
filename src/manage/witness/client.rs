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
