//! Read caller-bound user operation history without reserving or executing work.
//!
//! These GET resources require an existing `users:write` grant. The server checks
//! caller ownership in its read transaction; the wire response does not contain
//! an actor or payload digest that this client could independently authenticate.

use std::{collections::HashSet, io};

use serde::{Deserialize, Serialize};

use super::{ConnectionArgs, Response, input, store, views};
use crate::manage::views::{Operation, required_nullable};

const RESOURCE: &str = "/api/v1/proxy/user-operations";

/// All commands perform exactly one GET. A successful query may describe a
/// reserved or rejected write; it does not mean a change was applied or tested.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Read the current node, policy revision and ownership epoch
    Context(ContextArgs),
    /// Read one descending page of this caller's operation history
    List(ListArgs),
    /// Read an original operation ID without executing or replaying it
    Get(GetArgs),
}

/// Read the current context, optionally checking a previously known node ID.
#[derive(clap::Args)]
pub struct ContextArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Expected node ID, if already known; context alone is an observation
    #[arg(long)]
    node_id: Option<String>,
}

/// One history page for an explicitly expected node and the authenticated caller.
#[derive(clap::Args)]
pub struct ListArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Expected node ID for this history; not a target selected by the server
    #[arg(long)]
    node_id: String,
    /// Exclusive sequence cursor from the same node and caller's previous page
    #[arg(long)]
    before: Option<String>,
    /// Page size (1 to 50); never follow a continuation automatically
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u32).range(1..=50))]
    limit: u32,
}

/// Original receipt bindings; these values never become write parameters.
#[derive(clap::Args)]
pub struct GetArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Expected node ID from the original operation context
    #[arg(long)]
    node_id: String,
    /// Exact original operation ID; do not substitute the latest list entry
    #[arg(long)]
    id: String,
    /// Original expected policy revision, if retained; not the current revision
    #[arg(long)]
    expected_revision: Option<String>,
    /// Original ownership epoch, if retained; not the current epoch
    #[arg(long)]
    expected_epoch: Option<String>,
}

/// Validated arguments bind a response to the explicitly selected resource.
pub(super) enum Read {
    Context {
        node_id: Option<String>,
    },
    List {
        node_id: String,
        before: Option<u64>,
        limit: u32,
    },
    Get {
        node_id: String,
        id: String,
        expected_revision: Option<u64>,
        expected_epoch: Option<u64>,
    },
}

/// Current context is a separate snapshot, not a constraint on older records.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    node_id: String,
    policy_revision: String,
    expected_epoch: String,
    local: bool,
}

/// One explicitly requested page; absence from history cannot prove no effect.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    items: Vec<Operation>,
    #[serde(deserialize_with = "required_nullable")]
    next_cursor: Option<String>,
}

impl Read {
    /// Validate IDs and decimal bounds before loading a CA or secret header.
    pub(super) fn from_command(command: Command) -> io::Result<(ConnectionArgs, Self)> {
        let (connection, read) = match command {
            Command::Context(args) => {
                if args
                    .node_id
                    .as_deref()
                    .is_some_and(|id| !store::valid_id(id))
                {
                    return Err(input("invalid expected node ID"));
                }
                (
                    args.connection,
                    Self::Context {
                        node_id: args.node_id,
                    },
                )
            }
            Command::List(args) => {
                if !store::valid_id(&args.node_id) || !(1..=50).contains(&args.limit) {
                    return Err(input("invalid operation listing options"));
                }
                let before = optional_revision(args.before.as_deref())?;
                (
                    args.connection,
                    Self::List {
                        node_id: args.node_id,
                        before,
                        limit: args.limit,
                    },
                )
            }
            Command::Get(args) => {
                if !store::valid_id(&args.node_id) || !store::valid_id(&args.id) {
                    return Err(input("invalid operation or expected node ID"));
                }
                let expected_revision = optional_revision(args.expected_revision.as_deref())?;
                let expected_epoch = optional_revision(args.expected_epoch.as_deref())?;
                (
                    args.connection,
                    Self::Get {
                        node_id: args.node_id,
                        id: args.id,
                        expected_revision,
                        expected_epoch,
                    },
                )
            }
        };
        Ok((connection, read))
    }

    pub(super) fn path(&self) -> String {
        match self {
            Self::Context { .. } => format!("{RESOURCE}/context"),
            Self::List { before, limit, .. } => {
                let mut path = format!("{RESOURCE}?limit={limit}");
                if let Some(before) = before {
                    use std::fmt::Write as _;
                    // Formatting a String has no external writer that can fail.
                    let _ = write!(path, "&before={before}");
                }
                path
            }
            Self::Get { id, .. } => format!("{RESOURCE}/{id}"),
        }
    }

    /// Only the selected DTO can reach stdout. A non-queryable ID remains
    /// unknown; neither malformed responses nor missing records trigger writes.
    pub(super) fn decode(&self, bytes: &[u8]) -> io::Result<Response> {
        match self {
            Self::Context { node_id } => {
                let context: Context = decode(bytes)?;
                if !store::valid_id(&context.node_id)
                    || node_id.as_ref().is_some_and(|id| *id != context.node_id)
                {
                    return Err(response_error());
                }
                views::revision(&context.policy_revision).map_err(|_| response_error())?;
                views::revision(&context.expected_epoch).map_err(|_| response_error())?;
                Ok(Response::OperationContext(context))
            }
            Self::List {
                node_id,
                before,
                limit,
            } => {
                let page: Page = decode(bytes)?;
                if page.items.len() > *limit as usize {
                    return Err(response_error());
                }
                let mut previous = *before;
                let mut ids = HashSet::with_capacity(page.items.len());
                for item in &page.items {
                    let sequence = item.validate(node_id)?;
                    if previous.is_some_and(|previous| sequence >= previous)
                        || !ids.insert(item.id.as_str())
                    {
                        return Err(response_error());
                    }
                    previous = Some(sequence);
                }
                if let Some(cursor) = page.next_cursor.as_deref() {
                    let cursor = views::revision(cursor).map_err(|_| response_error())?;
                    // Sequences start at one, so a continuation at one cannot
                    // describe an older retained row even in a full page.
                    if cursor <= 1
                        || page.items.len() != *limit as usize
                        || Some(cursor) != previous
                    {
                        return Err(response_error());
                    }
                }
                Ok(Response::Operations(page))
            }
            Self::Get {
                node_id,
                id,
                expected_revision,
                expected_epoch,
            } => {
                let operation: Operation = decode(bytes)?;
                operation.validate(node_id)?;
                if operation.id != *id
                    || expected_revision
                        .is_some_and(|value| operation.expected_revision != value.to_string())
                    || expected_epoch
                        .is_some_and(|value| operation.expected_epoch != value.to_string())
                {
                    return Err(response_error());
                }
                Ok(Response::Operation(operation))
            }
        }
    }
}

fn optional_revision(value: Option<&str>) -> io::Result<Option<u64>> {
    value
        .map(views::revision)
        .transpose()
        .map_err(|_| input("expected a canonical positive decimal sequence, revision or epoch"))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_slice(bytes).map_err(|_| response_error())
}

fn response_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "inconsistent management operation response",
    )
}
