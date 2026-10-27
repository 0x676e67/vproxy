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

/// Cancellation drops the owned driver; no background task or retry survives.
async fn request(prepared: Prepared, budget: Duration) -> io::Result<Response> {
    let Prepared { connection, read } = prepared;
    let bytes =
        transport::request(connection, transport::Request::Get(read.path()), budget).await?;
    read.decode(&bytes)
}

#[cfg(test)]
pub(super) mod tests {
    //! Synthetic credentials and a private CA exercise only owned loopback peers.
    //! No existing database, certificate store, service or environment proxy changes.

    use std::{
        fs::{self, DirBuilder, OpenOptions},
        io::Write as _,
        path::PathBuf,
        sync::Arc,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
        sync::Notify,
        task::JoinSet,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::manage::tls;

    pub(super) const A: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    pub(super) const B: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    pub(super) const C: &str = "AgICAgICAgICAgICAgICAg";
    pub(super) const D: &str = "AwMDAwMDAwMDAwMDAwMDAw";
    pub(super) const TOKEN: &str =
        "vpa1.AAAAAAAAAAAAAAAAAAAAAA.1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub(super) const PRIVATE_BODY: &str = "remote-private-body-must-not-be-a-diagnostic";
    pub(super) const NETWORK_BUDGET: Duration = Duration::from_secs(5);

    fn args() -> UsersArgs {
        UsersArgs {
            connection: ConnectionArgs {
                origin: "https://127.0.0.1:1".into(),
                ca: PathBuf::from("not-read-by-input-tests.pem"),
                header_file: PathBuf::from("not-read-by-input-tests.header"),
            },
            name: None,
            id: None,
            after: None,
            limit: 2,
            include_deleted: false,
        }
    }

    fn user(id: &str, name: &str) -> Value {
        json!({
            "id": id, "name": name, "active": true, "deleted": false,
            "protocols": ["http", "socks5"], "concurrent_limit": 4, "revision": "2"
        })
    }

    fn page(items: Vec<Value>, next: Option<&str>) -> Value {
        json!({"revision": "9", "items": items, "next_cursor": next})
    }

    fn validate(read: &Read, value: Value) -> io::Result<()> {
        let value: Page<User> = serde_json::from_value(value).map_err(io::Error::other)?;
        read.validate_page(&value)
    }

    fn failure<T>(result: io::Result<T>) -> io::Result<io::Error> {
        result
            .err()
            .ok_or_else(|| io::Error::other("expected query rejection"))
    }

    #[test]
    fn explicit_read_modes_keep_query_literals_and_cursor_kinds_separate() -> io::Result<()> {
        let mut input = args();
        input.after = Some(A.into());
        assert_eq!(
            Read::from_args(&input)?.path(),
            format!("/api/v1/proxy/users?limit=2&include_deleted=false&after={A}")
        );
        input.after = None;
        input.name = Some("A+ /%_&中".into());
        assert_eq!(
            Read::from_args(&input)?.path(),
            "/api/v1/proxy/users/search?mode=name&q=A%2B+%2F%25_%26%E4%B8%AD&limit=2&include_deleted=false"
        );
        input.name = Some(A.into());
        assert!(Read::from_args(&input)?.path().contains("mode=name&q="));
        input.name = None;
        input.id = Some(A.into());
        assert!(Read::from_args(&input)?.path().contains("mode=id&q="));
        input.after = Some(B.into());
        assert!(Read::from_args(&input).is_err());
        input.after = None;
        input.name = Some("two modes".into());
        assert!(Read::from_args(&input).is_err());

        let query = Search::new(Mode::Name, "a".into(), false, 2, None)?;
        let cursor = query.next_cursor(A, 9, B)?;
        for limit in [0, 51] {
            for mode in [None, Some(Mode::Name), Some(Mode::Id)] {
                let mut input = args();
                input.limit = limit;
                match mode {
                    Some(Mode::Name) => input.name = Some("a".into()),
                    Some(Mode::Id) => input.id = Some(A.into()),
                    None => {}
                }
                assert!(Read::from_args(&input).is_err());
            }
        }
        for (name, after) in [(None, cursor), (Some("a"), A.into())] {
            let mut input = args();
            input.name = name.map(str::to_owned);
            input.after = Some(after);
            assert!(Read::from_args(&input).is_err());
        }
        for origin in [
            "http://127.0.0.1",
            "https://127.0.0.1/",
            "https://user@127.0.0.1",
            "https://127.0.0.1/path",
            "https://127.0.0.1?token=not-a-token",
        ] {
            let mut input = args();
            input.connection.origin = origin.into();
            // Missing fixture paths prove origin rejection happens before file I/O.
            assert_eq!(failure(prepare(input))?.kind(), io::ErrorKind::InvalidInput);
        }
        Ok(())
    }

    #[test]
    fn validated_pages_bind_revisions_order_filters_and_continuations() -> io::Result<()> {
        let read = Read::from_args(&args())?;
        validate(
            &read,
            page(vec![user(A, "Alpha"), user(B, "Beta")], Some(B)),
        )?;
        for invalid in [
            page(vec![user(B, "Beta"), user(A, "Alpha")], None),
            page(vec![user(A, "Alpha"), user(A, "Duplicate")], None),
            page(vec![user(A, "Alpha")], Some(A)),
            page(Vec::new(), Some(A)),
            page(vec![user(A, "Alpha"), user(B, "Beta")], Some(C)),
            page(
                vec![user(A, "Alpha"), user(B, "Beta"), user(C, "Gamma")],
                None,
            ),
        ] {
            assert!(validate(&read, invalid).is_err());
        }
        for revision in ["0", "01", "-1", "9223372036854775808"] {
            let mut invalid = page(vec![user(A, "Alpha")], None);
            invalid["revision"] = json!(revision);
            assert!(validate(&read, invalid).is_err());
        }
        for (field, value) in [
            ("revision", json!("10")),
            ("id", json!("not-an-id")),
            ("concurrent_limit", json!(0)),
            ("protocols", json!(["http", "http"])),
        ] {
            let mut invalid = user(A, "Alpha");
            invalid[field] = value;
            assert!(validate(&read, page(vec![invalid], None)).is_err());
        }
        let mut deleted = user(A, "Historical");
        deleted["active"] = json!(false);
        deleted["deleted"] = json!(true);
        assert!(validate(&read, page(vec![deleted.clone()], None)).is_err());
        let mut input = args();
        input.include_deleted = true;
        validate(&Read::from_args(&input)?, page(vec![deleted], None))?;
        input.include_deleted = false;
        input.after = Some(B.into());
        assert!(
            validate(
                &Read::from_args(&input)?,
                page(vec![user(A, "Alpha")], None)
            )
            .is_err()
        );

        let query = Search::new(Mode::Name, "a".into(), false, 2, None)?;
        let cursor = query.next_cursor(A, 9, B)?;
        input.after = None;
        input.name = Some("a".into());
        validate(
            &Read::from_args(&input)?,
            page(vec![user(A, "Alpha"), user(B, "Beta")], Some(&cursor)),
        )?;
        assert!(validate(&Read::from_args(&input)?, page(vec![user(A, "Zero")], None)).is_err());
        input.after = Some(cursor);
        let continued = Read::from_args(&input)?;
        validate(&continued, page(vec![user(C, "Gamma")], None))?;
        assert!(validate(&continued, page(vec![user(B, "Beta")], None)).is_err());
        let mut changed = page(vec![user(C, "Gamma")], None);
        changed["revision"] = json!("10");
        assert!(validate(&continued, changed).is_err());
        let next = query.next_cursor(C, 9, D)?;
        assert!(
            validate(
                &continued,
                page(vec![user(C, "Gamma"), user(D, "Delta")], Some(&next))
            )
            .is_err()
        );
        input.name = None;
        input.after = None;
        input.id = Some(A.into());
        validate(
            &Read::from_args(&input)?,
            page(vec![user(A, "Alpha")], None),
        )?;
        assert!(validate(&Read::from_args(&input)?, page(vec![user(B, "Beta")], None)).is_err());

        for nested in [false, true] {
            let mut unknown = page(vec![user(A, "Alpha")], None);
            if nested {
                unknown["items"][0]["secret"] = json!(PRIVATE_BODY);
            } else {
                unknown["secret"] = json!(PRIVATE_BODY);
            }
            assert!(serde_json::from_value::<Page<User>>(unknown).is_err());
        }
        let valid: Page<User> =
            serde_json::from_value(page(vec![user(A, "Alpha")], None)).map_err(io::Error::other)?;
        let mut output = Vec::new();
        write_response(&mut output, &valid)?;
        assert_eq!(
            serde_json::from_slice::<Value>(&output).map_err(io::Error::other)?,
            page(vec![user(A, "Alpha")], None)
        );
        struct Broken;
        impl io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            failure(write_response(&mut Broken, &valid))?.kind(),
            io::ErrorKind::BrokenPipe
        );
        Ok(())
    }

    /// Only this random, exclusively created leaf and its synthetic files are removed.
    pub(in crate::manage) struct Authority {
        root: PathBuf,
        issuer: CertifiedIssuer<'static, KeyPair>,
        pub(in crate::manage) ca: PathBuf,
        pub(in crate::manage) header: PathBuf,
    }

    impl Authority {
        pub(in crate::manage) fn new() -> io::Result<Self> {
            let mut random = [0; 16];
            getrandom::fill(&mut random)
                .map_err(|_| io::Error::other("test entropy unavailable"))?;
            let root = std::env::temp_dir().join(format!(
                "vproxy-query-test-{:032x}",
                u128::from_be_bytes(random)
            ));
            let mut parameters =
                CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
            parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            parameters.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let issuer = CertifiedIssuer::self_signed(
                parameters,
                KeyPair::generate().map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            let builder = DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&root)?;
            let mut authority = Self {
                root,
                issuer,
                ca: PathBuf::new(),
                header: PathBuf::new(),
            };
            authority.ca = authority.write("ca.pem", authority.issuer.pem().as_bytes())?;
            authority.header = authority.write(
                "credential.header",
                format!("Authorization: Bearer {TOKEN}\n").as_bytes(),
            )?;
            Ok(authority)
        }

        pub(in crate::manage) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<PathBuf> {
            let path = self.root.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options.open(&path)?.write_all(bytes)?;
            Ok(path)
        }

        pub(in crate::manage) fn config(
            &self,
            label: &str,
            name: &str,
            alpn: &[u8],
        ) -> io::Result<Arc<rustls::ServerConfig>> {
            let mut parameters =
                CertificateParams::new(vec![name.into()]).map_err(io::Error::other)?;
            parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            let key = KeyPair::generate().map_err(io::Error::other)?;
            let certificate = parameters
                .signed_by(&key, &self.issuer)
                .map_err(io::Error::other)?;
            let cert_path =
                self.write(&format!("{label}-cert.pem"), certificate.pem().as_bytes())?;
            let key_path =
                self.write(&format!("{label}-key.pem"), key.serialize_pem().as_bytes())?;
            let mut config = (*tls::admin_server_config(&cert_path, &key_path)?).clone();
            config.alpn_protocols = if alpn.is_empty() {
                Vec::new()
            } else {
                vec![alpn.to_vec()]
            };
            Ok(Arc::new(config))
        }

        fn args(&self, origin: &str) -> UsersArgs {
            UsersArgs {
                connection: ConnectionArgs {
                    origin: origin.into(),
                    ca: self.ca.clone(),
                    header_file: self.header.clone(),
                },
                ..args()
            }
        }
    }

    impl Drop for Authority {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct Observed {
        connections: AtomicUsize,
        http_bytes: AtomicUsize,
        requests: AtomicUsize,
        closed: AtomicUsize,
        extra_http: AtomicUsize,
        sent: Notify,
        peer_closed: Notify,
    }

    pub(super) struct Peer {
        pub(super) origin: String,
        observed: Arc<Observed>,
    }

    pub(super) struct Reply {
        pub(super) status: u16,
        body: Vec<u8>,
        close: bool,
        partial: bool,
        extra_headers: String,
    }

    impl Reply {
        pub(super) fn json(value: Value) -> io::Result<Self> {
            Ok(Self {
                status: 200,
                body: serde_json::to_vec(&value).map_err(io::Error::other)?,
                close: false,
                partial: false,
                extra_headers: String::new(),
            })
        }
    }

    fn closed(observed: &Observed) {
        observed.closed.fetch_add(1, Ordering::SeqCst);
        observed.peer_closed.notify_one();
    }

    async fn peer(
        tasks: &mut JoinSet<io::Result<()>>,
        config: Arc<rustls::ServerConfig>,
        reply: Reply,
    ) -> io::Result<Peer> {
        peer_at(tasks, config, reply, None).await
    }

    /// Operations fixtures bind the entire request target, including pagination.
    pub(super) async fn peer_at(
        tasks: &mut JoinSet<io::Result<()>>,
        config: Arc<rustls::ServerConfig>,
        reply: Reply,
        expected_path: Option<&str>,
    ) -> io::Result<Peer> {
        let expected_line = expected_path.map(|path| format!("GET {path} HTTP/1.1"));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let origin = format!("https://{}", listener.local_addr()?);
        let observed = Arc::new(Observed::default());
        let counters = observed.clone();
        tasks.spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        loop {
            let (socket, _) = listener.accept().await?;
            counters.connections.fetch_add(1, Ordering::SeqCst);
            let mut stream = match acceptor.accept(socket).await {
                Ok(stream) => stream,
                Err(_) => { closed(&counters); continue; }
            };
            let mut headers = Vec::new();
            let mut buffer = [0; 1024];
            while !headers.windows(4).any(|part| part == b"\r\n\r\n") {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => { closed(&counters); break; }
                    Ok(length) => {
                        counters.http_bytes.fetch_add(length, Ordering::SeqCst);
                        headers.extend_from_slice(&buffer[..length]);
                        if headers.len() > 8192 { return Err(io::Error::other("test request exceeds fixture limit")); }
                    }
                }
            }
            if !headers.windows(4).any(|part| part == b"\r\n\r\n") { continue; }
            let text = std::str::from_utf8(&headers).map_err(|_| io::Error::other("invalid test request header"))?;
            let authorization = text.lines().filter_map(|line| line.split_once(':')).filter(|(name, _)| name.eq_ignore_ascii_case("authorization")).collect::<Vec<_>>();
            let valid_target = expected_line.as_ref().map_or_else(
                || text.starts_with("GET /api/v1/proxy/users"),
                |line| text.lines().next() == Some(line.as_str()),
            );
            if !valid_target
                || authorization.len() != 1
                || authorization[0].1.trim() != format!("Bearer {TOKEN}")
            { return Err(io::Error::other("unexpected test query or authorization")); }
            counters.requests.fetch_add(1, Ordering::SeqCst);
            let connection = if reply.close { "close" } else { "keep-alive" };
            let head = format!("HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n{}\r\n", reply.status, reply.body.len(), reply.extra_headers);
            let end = if reply.partial { reply.body.len().min(1) } else { reply.body.len() };
            if async {
                stream.write_all(head.as_bytes()).await?;
                stream.write_all(&reply.body[..end]).await?;
                stream.flush().await
            }.await.is_err() {
                closed(&counters);
                continue;
            }
            counters.sent.notify_one();
            if reply.close && stream.shutdown().await.is_err() {
                closed(&counters);
                continue;
            }
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => { closed(&counters); break; }
                    Ok(length) => { counters.extra_http.fetch_add(length, Ordering::SeqCst); }
                }
            }
        }
    });
        Ok(Peer { origin, observed })
    }

    pub(super) async fn wait_closed(peer: &Peer) -> io::Result<()> {
        tokio::time::timeout(NETWORK_BUDGET, async {
            while peer.observed.closed.load(Ordering::SeqCst) == 0 {
                peer.observed.peer_closed.notified().await;
            }
        })
        .await
        .map_err(|_| io::Error::other("query did not close its loopback connection"))
    }

    pub(super) fn one_request(peer: &Peer) {
        assert_eq!(peer.observed.connections.load(Ordering::SeqCst), 1);
        assert_eq!(peer.observed.requests.load(Ordering::SeqCst), 1);
        assert_eq!(peer.observed.extra_http.load(Ordering::SeqCst), 0);
    }

    /// Abort and join all fixture listeners on ordinary errors as well as success.
    /// These are async socket tasks only; no blocking worker can outlive the fixture.
    pub(in crate::manage) async fn finish(
        tasks: &mut JoinSet<io::Result<()>>,
        outcome: io::Result<()>,
    ) -> io::Result<()> {
        tasks.abort_all();
        let mut cleanup = Ok(());
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Err(error)) => {
                    cleanup = Err(error);
                }
                Err(error) if !error.is_cancelled() => {
                    cleanup = Err(io::Error::other(error));
                }
                _ => {}
            }
        }
        outcome.and(cleanup)
    }

    #[test]
    fn real_https_verifies_ca_san_and_alpn_before_sending_one_header() -> io::Result<()> {
        let authority = Authority::new()?;
        let other = Authority::new()?;
        // Runtime destruction precedes certificate directory cleanup, even on panic.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut tasks = JoinSet::new();
            let outcome = async {
                for close in [false, true] {
                    let label = if close { "close" } else { "keepalive" };
                    let mut reply = Reply::json(page(vec![user(A, "Alpha")], None))?;
                    reply.close = close;
                    let server = peer(
                        &mut tasks,
                        authority.config(label, "127.0.0.1", b"http/1.1")?,
                        reply,
                    )
                    .await?;
                    let result =
                        request(prepare(authority.args(&server.origin))?, NETWORK_BUDGET).await?;
                    let Response::Users(result) = result else {
                        return Err(io::Error::other("expected user query response"));
                    };
                    assert_eq!(result.items.len(), 1);
                    wait_closed(&server).await?;
                    one_request(&server);
                }
                for (label, name, alpn, wrong_ca) in [
                    ("wrong-ca", "127.0.0.1", &b"http/1.1"[..], true),
                    ("wrong-san", "localhost", &b"http/1.1"[..], false),
                    ("wrong-alpn", "127.0.0.1", &b"h2"[..], false),
                    ("missing-alpn", "127.0.0.1", &b""[..], false),
                ] {
                    let server = peer(
                        &mut tasks,
                        authority.config(label, name, alpn)?,
                        Reply::json(page(Vec::new(), None))?,
                    )
                    .await?;
                    let mut input = authority.args(&server.origin);
                    if wrong_ca {
                        input.connection.ca = other.ca.clone();
                    }
                    let error = failure(request(prepare(input)?, NETWORK_BUDGET).await)?;
                    assert!(!error.to_string().contains(TOKEN));
                    wait_closed(&server).await?;
                    assert_eq!(server.observed.http_bytes.load(Ordering::SeqCst), 0);
                    assert_eq!(server.observed.requests.load(Ordering::SeqCst), 0);
                }
                Ok(())
            }
            .await;
            finish(&mut tasks, outcome).await
        })
    }

    #[test]
    fn real_https_rejections_and_unknown_fields_never_echo_remote_secrets_or_retry()
    -> io::Result<()> {
        let authority = Authority::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut tasks = JoinSet::new();
            let outcome = async {
                let destination = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
                destination.set_nonblocking(true)?;
                let mut redirect = Reply::json(json!({"secret": PRIVATE_BODY}))?;
                redirect.status = 302;
                redirect.extra_headers = format!(
                    "Location: https://{}/do-not-contact\r\n",
                    destination.local_addr()?
                );
                let server = peer(
                    &mut tasks,
                    authority.config("redirect", "127.0.0.1", b"http/1.1")?,
                    redirect,
                )
                .await?;
                let error = failure(
                    request(prepare(authority.args(&server.origin))?, NETWORK_BUDGET).await,
                )?;
                assert_eq!(
                    error.to_string(),
                    "management query rejected (302, redirect_refused)"
                );
                assert_eq!(
                    destination.accept().err().map(|error| error.kind()),
                    Some(io::ErrorKind::WouldBlock)
                );
                wait_closed(&server).await?;
                one_request(&server);

                for (index, status, code, expected) in [
                    (
                        0,
                        401,
                        "invalid_token",
                        "management query rejected (401, invalid_token)",
                    ),
                    (
                        1,
                        500,
                        PRIVATE_BODY,
                        "management query rejected (500, request_rejected)",
                    ),
                    (
                        2,
                        403,
                        "invalid_token",
                        "management query rejected (403, request_rejected)",
                    ),
                ] {
                    let mut reply = Reply::json(
                        json!({"error": {"code": code, "detail": PRIVATE_BODY}, "token": TOKEN}),
                    )?;
                    reply.status = status;
                    let server = peer(
                        &mut tasks,
                        authority.config(&format!("status-{index}"), "127.0.0.1", b"http/1.1")?,
                        reply,
                    )
                    .await?;
                    let error = failure(
                        request(prepare(authority.args(&server.origin))?, NETWORK_BUDGET).await,
                    )?;
                    assert_eq!(error.to_string(), expected);
                    assert!(!error.to_string().contains(TOKEN));
                    assert!(!error.to_string().contains(PRIVATE_BODY));
                    wait_closed(&server).await?;
                    one_request(&server);
                }
                for index in 0..4 {
                    let mut wire = page(vec![user(A, "Alpha")], None);
                    if index == 0 {
                        wire["items"][0]["credential"] = json!(PRIVATE_BODY);
                    }
                    let mut reply = Reply::json(wire)?;
                    match index {
                        1 => reply.body = vec![b'x'; 32 * 1024 + 1],
                        2 => reply.extra_headers = "Content-Encoding: gzip\r\n".into(),
                        3 => reply.extra_headers = "Content-Type: application/json\r\n".into(),
                        _ => {}
                    }
                    let server = peer(
                        &mut tasks,
                        authority.config(&format!("invalid-{index}"), "127.0.0.1", b"http/1.1")?,
                        reply,
                    )
                    .await?;
                    let error = failure(
                        request(prepare(authority.args(&server.origin))?, NETWORK_BUDGET).await,
                    )?;
                    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                    assert!(!error.to_string().contains(PRIVATE_BODY));
                    wait_closed(&server).await?;
                    one_request(&server);
                }
                let mut truncated = Reply::json(page(vec![user(A, "Alpha")], None))?;
                truncated.partial = true;
                truncated.close = true;
                let server = peer(
                    &mut tasks,
                    authority.config("truncated", "127.0.0.1", b"http/1.1")?,
                    truncated,
                )
                .await?;
                let error = failure(
                    request(prepare(authority.args(&server.origin))?, NETWORK_BUDGET).await,
                )?;
                assert_ne!(error.kind(), io::ErrorKind::TimedOut);
                assert!(!error.to_string().contains(TOKEN));
                wait_closed(&server).await?;
                one_request(&server);
                Ok(())
            }
            .await;
            finish(&mut tasks, outcome).await
        })
    }

    #[test]
    fn body_deadline_and_dropping_the_owned_request_close_the_actual_tls_connection()
    -> io::Result<()> {
        let authority = Authority::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
        let mut tasks = JoinSet::new();
        let outcome = async {
            for cancel in [false, true] {
                let label = if cancel { "cancel" } else { "deadline" };
                let mut reply = Reply::json(page(vec![user(A, "Alpha")], None))?;
                reply.partial = true;
                let server = peer(&mut tasks, authority.config(label, "127.0.0.1", b"http/1.1")?, reply).await?;
                let budget = if cancel { NETWORK_BUDGET } else { Duration::from_secs(1) };
                let mut request = Box::pin(request(prepare(authority.args(&server.origin))?, budget));
                tokio::select! {
                    _ = server.observed.sent.notified() => {}
                    _ = &mut request => return Err(io::Error::other("request ended before the slow body was observed")),
                }
                if cancel { drop(request); }
                else {
                    let error = failure(request.await)?;
                    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                    assert_eq!(error.to_string(), "management query timed out");
                }
                wait_closed(&server).await?;
                one_request(&server);
            }
            Ok(())
        }.await;
        finish(&mut tasks, outcome).await
    })
    }
}
