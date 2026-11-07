//! Single-request developer queries using an explicitly scoped automation grant.
//!
//! No local database, browser session or node private key is loaded. The caller
//! selects an explicit HTTPS origin/CA and an issued private header file; neither
//! a response nor a continuation can change the destination or grant authority.

mod operations;

use std::{
    io::{self, Write},
    time::Duration,
};

use super::{
    client::{self as transport, Connection, ConnectionArgs},
    store,
    user_search::{Mode, Query as Search},
    views::{self, Page, User},
};
use clap::Subcommand;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Read-only API commands. Pagination is explicit; no operation retries itself.
#[derive(Subcommand)]
pub enum Command {
    /// Print one validated user page as JSON
    Users(UsersArgs),
    /// Read local user operation context, history or an original operation ID
    #[command(subcommand)]
    Operations(operations::Command),
}

/// Non-secret user filters. Pagination never changes the selected destination.
#[derive(clap::Args)]
pub struct UsersArgs {
    #[command(flatten)]
    connection: ConnectionArgs,
    /// Literal display-name substring, not a wildcard or an identity
    #[arg(long, conflicts_with = "id")]
    name: Option<String>,
    /// Exact user ID, distinct from a display name
    #[arg(long, conflicts_with_all = ["name", "after"])]
    id: Option<String>,
    /// Continuation from the same listing or search with unchanged options
    #[arg(long)]
    after: Option<String>,
    /// Page size (1 to 50); this command never reads all pages automatically
    #[arg(long, default_value_t = 25, value_parser = clap::value_parser!(u32).range(1..=50))]
    limit: u32,
    /// Include permanently deleted user metadata
    #[arg(long)]
    include_deleted: bool,
}

/// Validated fixed read, not an arbitrary request path or a mutation envelope.
enum Read {
    List {
        after: Option<String>,
        limit: u32,
        include_deleted: bool,
    },
    Search(Search),
    Operations(operations::Read),
}

/// Validated public data only; arbitrary peer JSON is never printed directly.
#[derive(serde::Serialize)]
#[serde(untagged)]
enum Response {
    Users(Page<User>),
    OperationContext(operations::Context),
    Operations(operations::Page),
    Operation(views::Operation),
}

impl Read {
    fn from_args(args: &UsersArgs) -> io::Result<Self> {
        match (&args.name, &args.id) {
            (Some(_), Some(_)) => Err(input("choose either --name or --id")),
            (name, id) if name.is_some() || id.is_some() => {
                let (mode, term) = match (name, id) {
                    (Some(name), _) => (Mode::Name, name),
                    (_, Some(id)) => (Mode::Id, id),
                    _ => return Err(input("missing search input")),
                };
                Search::new(
                    mode,
                    term.clone(),
                    args.include_deleted,
                    args.limit,
                    args.after.clone(),
                )
                .map(Self::Search)
            }
            _ => {
                if !(1..=50).contains(&args.limit)
                    || args.after.as_deref().is_some_and(|id| !store::valid_id(id))
                {
                    return Err(input("invalid user listing options"));
                }
                Ok(Self::List {
                    after: args.after.clone(),
                    limit: args.limit,
                    include_deleted: args.include_deleted,
                })
            }
        }
    }

    /// Fixed resources only; no input can select a write or arbitrary route.
    fn path(&self) -> String {
        let mut parameters = url::form_urlencoded::Serializer::new(String::new());
        let (path, after, limit, include_deleted) = match self {
            Self::List {
                after,
                limit,
                include_deleted,
            } => (
                "/api/v1/proxy/users",
                after.as_deref(),
                *limit,
                *include_deleted,
            ),
            Self::Search(query) => {
                parameters.append_pair("mode", query.mode().as_str());
                parameters.append_pair("q", query.q());
                (
                    "/api/v1/proxy/users/search",
                    query.after(),
                    query.limit(),
                    query.include_deleted(),
                )
            }
            Self::Operations(read) => return read.path(),
        };
        parameters.append_pair("limit", &limit.to_string());
        parameters.append_pair(
            "include_deleted",
            if include_deleted { "true" } else { "false" },
        );
        if let Some(after) = after {
            parameters.append_pair("after", after);
        }
        format!("{path}?{}", parameters.finish())
    }

    /// Check relationships as well as types before any response reaches stdout.
    /// A search cursor is an observation, not independent proof of node identity.
    fn validate_page(&self, page: &Page<User>) -> io::Result<()> {
        let revision = views::revision(&page.revision)?;
        let (limit, include_deleted, mut previous) = match self {
            Self::List {
                after,
                limit,
                include_deleted,
            } => (*limit, *include_deleted, after.as_deref()),
            Self::Search(query) => (query.limit(), query.include_deleted(), None),
            Self::Operations(_) => return Err(response_error()),
        };
        if page.items.len() > limit as usize {
            return Err(response_error());
        }
        for user in &page.items {
            views::validate_user(user)?;
            if views::revision(&user.revision)? > revision
                || (!include_deleted && user.deleted)
                || previous.is_some_and(|id| user.id.as_str() <= id)
                || matches!(self, Self::Search(query) if !query.matches(&user.id, &user.name))
            {
                return Err(response_error());
            }
            previous = Some(&user.id);
        }
        if page.next_cursor.is_some() && page.items.len() != limit as usize {
            return Err(response_error());
        }
        let first = page.items.first().map(|user| user.id.as_str());
        let last = page.items.last().map(|user| user.id.as_str());
        match self {
            Self::List { .. } => {
                if let Some(cursor) = page.next_cursor.as_deref()
                    && (Some(cursor) != last || !store::valid_id(cursor))
                {
                    return Err(response_error());
                }
            }
            Self::Search(query) => query
                .check_page(revision, first, last, page.next_cursor.as_deref())
                .map_err(|_| response_error())?,
            Self::Operations(_) => return Err(response_error()),
        }
        Ok(())
    }

    /// Decode the selected resource and check its relationships before output.
    fn decode(&self, bytes: &[u8]) -> io::Result<Response> {
        if let Self::Operations(read) = self {
            return read.decode(bytes);
        }
        let page = serde_json::from_slice::<Page<User>>(bytes).map_err(|_| response_error())?;
        self.validate_page(&page)?;
        Ok(Response::Users(page))
    }
}

/// Startup-only owned inputs. The header has no printable or serializable API.
struct Prepared {
    connection: Connection,
    read: Read,
}

/// Finish all input and synchronous file checks before any socket is opened.
fn prepare(args: UsersArgs) -> io::Result<Prepared> {
    let read = Read::from_args(&args)?;
    prepare_read(args.connection, read)
}

/// Resolve only validated reads. No synchronous input failure opens a socket.
fn prepare_read(args: ConnectionArgs, read: Read) -> io::Result<Prepared> {
    Ok(Prepared {
        connection: Connection::prepare(args)?,
        read,
    })
}

/// Query once, then write one JSON document. Errors never print an HTTP body.
///
/// Network and response waits share ten seconds. The runtime allows five more
/// seconds for its shutdown; an OS DNS resolver may still outlive that wait.
/// This is not a hard whole-process deadline or a blocking-thread kill facility.
pub(super) fn run(command: Command) -> io::Result<()> {
    let prepared = match command {
        Command::Users(args) => prepare(args)?,
        Command::Operations(command) => {
            let (connection, read) = operations::Read::from_command(command)?;
            prepare_read(connection, Read::Operations(read))?
        }
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()?;
    let result = runtime.block_on(request(prepared, REQUEST_TIMEOUT));
    runtime.shutdown_timeout(Duration::from_secs(5));
    let response = result?;
    write_response(&mut io::stdout().lock(), &response)
}

fn write_response(output: &mut impl Write, response: &impl serde::Serialize) -> io::Result<()> {
    serde_json::to_writer(&mut *output, response).map_err(|error| {
        io::Error::new(
            error.io_error_kind().unwrap_or(io::ErrorKind::Other),
            "cannot write query JSON output",
        )
    })?;
    writeln!(output)
}

fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn response_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "inconsistent management query response",
    )
}

/// Cancellation closes the request; the client keeps no idle connection or retry.
async fn request(prepared: Prepared, budget: Duration) -> io::Result<Response> {
    let Prepared { connection, read } = prepared;
    let bytes =
        transport::request(connection, transport::Request::Get(read.path()), budget).await?;
    read.decode(&bytes)
}
