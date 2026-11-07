//! Explicit local user writes over HTTPS, separate from read-only queries.
//!
//! Reserve and execute are independent single requests. No failure, cancellation,
//! missing response or missing stdout permits an automatic replacement request.

use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

use serde::Serialize;

use super::views::Operation;
use super::{
    client::{self, Connection, ConnectionArgs},
    files,
    store::{self, operations::UserChange},
    views,
};

const MAX_JSON_BYTES: usize = 4096;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Each command submits one POST. It never reads context or follows up by
/// executing, polling or repeating another request, even after a lost result.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Reserve an operation ID without changing a user; preserve the returned ID
    Reserve(ChangeArgs),
    /// Execute the original reservation using the same change and expected values
    Execute {
        #[command(flatten)]
        change: ChangeArgs,
        /// Original server-issued operation ID, never the latest history entry
        #[arg(long)]
        id: String,
    },
}

/// Non-secret expected values are supplied explicitly, not discovered and
/// automatically refreshed before a write. Only the four UserChange actions fit.
#[derive(clap::Args)]
pub struct ChangeArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Expected stable node ID; the server checks it before any operation write
    #[arg(long)]
    node_id: String,
    /// Original positive decimal policy revision from an explicit context read
    #[arg(long)]
    expected_revision: String,
    /// Original positive decimal policy ownership epoch
    #[arg(long)]
    expected_epoch: String,
    /// Bounded regular JSON file containing only a non-secret UserChange object
    #[arg(long)]
    change_file: PathBuf,
}

/// The node assertion is mandatory here even though older browser callers may
/// omit it. Old servers must reject the extra field; no fallback drops it.
#[derive(Serialize)]
struct Input {
    expected_node_id: String,
    expected_revision: String,
    expected_epoch: String,
    change: UserChange,
}

struct Prepared {
    connection: Connection,
    input: Input,
    id: Option<String>,
    json: Vec<u8>,
}

/// Validate identifiers, CAS, regular bounded JSON and policy before loading a
/// CA/header or opening a socket. No error echoes JSON, names or file contents.
fn prepare(command: Command) -> io::Result<Prepared> {
    let (args, id) = match command {
        Command::Reserve(args) => (args, None),
        Command::Execute { change, id } => (change, Some(id)),
    };
    if !store::valid_id(&args.node_id) || id.as_deref().is_some_and(|id| !store::valid_id(id)) {
        return Err(input_error("invalid expected node or operation ID"));
    }
    views::revision(&args.expected_revision)
        .and_then(|_| views::revision(&args.expected_epoch))
        .map_err(|_| input_error("expected canonical positive revision and epoch"))?;
    let bytes = files::read(&args.change_file, MAX_JSON_BYTES, false)
        .map_err(|error| io::Error::new(error.kind(), "cannot read bounded regular change JSON"))?;
    let change: UserChange = serde_json::from_slice(&bytes)
        .map_err(|_| input_error("invalid non-secret user change JSON"))?;
    change
        .validate()
        .map_err(|_| input_error("invalid non-secret user change"))?;
    let input = Input {
        expected_node_id: args.node_id,
        expected_revision: args.expected_revision,
        expected_epoch: args.expected_epoch,
        change,
    };
    let json = serde_json::to_vec(&input)
        .map_err(|_| input_error("cannot encode non-secret user change"))?;
    if json.len() > MAX_JSON_BYTES {
        return Err(input_error("user operation JSON exceeds its size limit"));
    }
    Ok(Prepared {
        connection: Connection::prepare(args.connection)?,
        input,
        id,
        json,
    })
}

/// Validate the same strict historical DTO as GET, plus this submission's
/// original CAS, action and target user. This is not runtime application proof.
fn decode(bytes: &[u8], input: &Input, id: Option<&str>) -> io::Result<Operation> {
    let operation: Operation = serde_json::from_slice(bytes).map_err(|_| response_error())?;
    operation.validate(&input.expected_node_id)?;
    if operation.expected_revision != input.expected_revision
        || operation.expected_epoch != input.expected_epoch
        || operation.action != input.change.action()
        || input
            .change
            .user_id()
            .is_some_and(|id| operation.user_id.as_deref() != Some(id))
        || match id {
            Some(id) => operation.id != id || operation.state == "reserved",
            None => operation.state != "reserved",
        }
    {
        return Err(response_error());
    }
    Ok(operation)
}

/// The connection, exchange and driver remain owned by this future. A caller
/// cancelling it cannot leave a retry, poll or detached task running locally.
async fn request(prepared: Prepared, budget: Duration) -> io::Result<Operation> {
    let Prepared {
        connection,
        input,
        id,
        json,
    } = prepared;
    let request = match &id {
        Some(id) => client::Request::Execute {
            id: id.clone(),
            json,
        },
        None => client::Request::Reserve(json),
    };
    let bytes = client::request(connection, request, budget)
        .await
        .map_err(unknown)?;
    decode(&bytes, &input, id.as_deref()).map_err(unknown)
}

/// Submit once, then print a validated non-secret historical record. A failed
/// stdout may hide a successfully reserved/executed ID and never permits replay.
pub(super) fn run(command: Command) -> io::Result<()> {
    let prepared = prepare(command)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    let result = runtime.block_on(request(prepared, REQUEST_TIMEOUT));
    runtime.shutdown_timeout(Duration::from_secs(5));
    write_response(&mut io::stdout().lock(), &result?)
}

fn write_response(output: &mut impl Write, operation: &Operation) -> io::Result<()> {
    serde_json::to_writer(&mut *output, operation)
        .map_err(|error| output_error(error.io_error_kind().unwrap_or(io::ErrorKind::Other)))?;
    writeln!(output)
        .and_then(|()| output.flush())
        .map_err(|error| output_error(error.kind()))
}

fn unknown(error: io::Error) -> io::Error {
    // All inner diagnostics come from this client's fixed stage/code allowlist.
    // No remote body, user name, path or credential is interpolated here.
    io::Error::new(
        error.kind(),
        format!(
            "{error}; outcome may be unknown; do not repeat the submission or infer its ID from history"
        ),
    )
}

fn output_error(kind: io::ErrorKind) -> io::Error {
    io::Error::new(
        kind,
        "operation response was validated but output failed; preserve the original ID if available and do not repeat the submission",
    )
}

fn input_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn response_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "inconsistent management operation response",
    )
}
