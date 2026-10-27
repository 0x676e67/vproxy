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

#[cfg(test)]
mod tests {
    //! Synthetic one-request HTTPS writes; no database, existing credential or trust
    //! store is opened. The old query fixture supplies the CA and private header.

    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
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
    use crate::manage::query::tests::{Authority, finish};

    const NODE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
    const ID: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
    const USER: &str = "AgICAgICAgICAgICAgICAg";
    const OTHER: &str = "AwMDAwMDAwMDAwMDAwMDAw";
    const TOKEN: &str = "vpa1.AAAAAAAAAAAAAAAAAAAAAA.1.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const PRIVATE: &str = "remote-private-body-not-for-output";
    const BUDGET: Duration = Duration::from_secs(5);

    fn args(path: PathBuf) -> ChangeArgs {
        ChangeArgs {
            connection: ConnectionArgs {
                origin: "https://127.0.0.1:1".into(),
                ca: "missing-ca-not-read-on-invalid-input.pem".into(),
                header_file: "missing-header-not-read-on-invalid-input.header".into(),
            },
            node_id: NODE.into(),
            expected_revision: "7".into(),
            expected_epoch: "3".into(),
            change_file: path,
        }
    }

    fn change(action: &str) -> Value {
        match action {
            "create_user" => {
                json!({"action":action,"name":"Example","protocols":["http","socks5"],"concurrent_limit":4})
            }
            "update_user" => {
                json!({"action":action,"id":USER,"name":"Example","protocols":["http","socks5"],"concurrent_limit":4})
            }
            "set_user_active" => json!({"action":action,"id":USER,"active":true}),
            _ => json!({"action":"delete_user","id":USER}),
        }
    }

    fn input(action: &str) -> io::Result<Input> {
        Ok(Input {
            expected_node_id: NODE.into(),
            expected_revision: "7".into(),
            expected_epoch: "3".into(),
            change: serde_json::from_value(change(action)).map_err(io::Error::other)?,
        })
    }

    fn result(action: &str, state: &str) -> Value {
        json!({
            "id":ID,"node_id":NODE,"sequence":"9","expected_revision":"7","expected_epoch":"3",
            "action":action,"user_id":if state!="saved" && action=="create_user" {Value::Null} else {json!(USER)},
            "state":state,"saved_revision":if state=="saved" {json!("8")} else {Value::Null},
            "rejection":if state=="rejected" {json!("policy_conflict")} else {Value::Null},
        })
    }

    fn failed<T>(value: io::Result<T>) -> io::Result<io::Error> {
        value
            .err()
            .ok_or_else(|| io::Error::other("expected explicit operation rejection"))
    }

    #[test]
    fn validates_ids_cas_bounded_regular_change_and_policy_before_ca_or_header() -> io::Result<()> {
        let authority = Authority::new()?;
        let absent = PathBuf::from("not-opened-invalid-input.json");
        for value in ["", "0", "01", "+1", "9223372036854775808"] {
            let mut a = args(absent.clone());
            a.expected_revision = value.into();
            assert_eq!(
                failed(prepare(Command::Reserve(a)))?.kind(),
                io::ErrorKind::InvalidInput
            );
            let mut a = args(absent.clone());
            a.expected_epoch = value.into();
            assert_eq!(
                failed(prepare(Command::Reserve(a)))?.kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for id in ["", "../execute", "AAAAAAAAAAAAAAAAAAAAAB"] {
            let mut a = args(absent.clone());
            a.node_id = id.into();
            assert_eq!(
                failed(prepare(Command::Reserve(a)))?.kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                failed(prepare(Command::Execute {
                    change: args(absent.clone()),
                    id: id.into()
                }))?
                .kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let mut unknown = change("create_user");
        unknown["password"] = json!(PRIVATE);
        let mut duplicate = change("create_user");
        duplicate["protocols"] = json!(["http", "http"]);
        let mut bad_id = change("delete_user");
        bad_id["id"] = json!("not-an-id");
        let mut invalid_name = change("create_user");
        invalid_name["name"] = json!("\n");
        let mut zero = change("create_user");
        zero["concurrent_limit"] = json!(0);
        for (index, value) in [
            unknown,
            duplicate,
            bad_id,
            invalid_name,
            zero,
            json!({"action":"rotate_credential"}),
        ]
        .into_iter()
        .enumerate()
        {
            let path = authority.write(
                &format!("invalid-{index}.json"),
                &serde_json::to_vec(&value).map_err(io::Error::other)?,
            )?;
            let error = failed(prepare(Command::Reserve(args(path))))?;
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!error.to_string().contains(PRIVATE));
        }
        for (index, bytes) in [
            b"{".to_vec(),
            vec![b' '; MAX_JSON_BYTES + 1],
            b"{\"action\":\"delete_user\",\"action\":\"delete_user\"}".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let path = authority.write(&format!("bad-json-{index}.json"), &bytes)?;
            assert_eq!(
                failed(prepare(Command::Reserve(args(path))))?.kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let directory = authority
            .ca
            .parent()
            .ok_or_else(|| io::Error::other("fixture parent absent"))?
            .to_owned();
        assert_eq!(
            failed(prepare(Command::Reserve(args(directory))))?.kind(),
            io::ErrorKind::InvalidInput
        );
        let path = authority.write(
            "valid-before-missing-ca.json",
            &serde_json::to_vec(&change("create_user")).map_err(io::Error::other)?,
        )?;
        // A valid change gets as far as the absent CA, rather than being rejected
        // by this command's parser; no network is possible before that check.
        assert_eq!(
            failed(prepare(Command::Reserve(args(path))))?.kind(),
            io::ErrorKind::NotFound
        );
        Ok(())
    }

    #[test]
    fn responses_bind_original_node_id_cas_action_user_and_expected_phase() -> io::Result<()> {
        for action in [
            "create_user",
            "update_user",
            "set_user_active",
            "delete_user",
        ] {
            let input = input(action)?;
            decode(
                &serde_json::to_vec(&result(action, "reserved")).map_err(io::Error::other)?,
                &input,
                None,
            )?;
            for state in ["saved", "rejected"] {
                decode(
                    &serde_json::to_vec(&result(action, state)).map_err(io::Error::other)?,
                    &input,
                    Some(ID),
                )?;
            }
        }
        let input = input("update_user")?;
        for (field, value) in [
            ("id", json!(OTHER)),
            ("node_id", json!(OTHER)),
            ("expected_revision", json!("6")),
            ("expected_epoch", json!("4")),
            ("action", json!("set_user_active")),
            ("user_id", json!(OTHER)),
            ("saved_revision", json!("9")),
            ("secret", json!(PRIVATE)),
        ] {
            let mut value_body = result("update_user", "saved");
            value_body[field] = value;
            assert!(
                decode(
                    &serde_json::to_vec(&value_body).map_err(io::Error::other)?,
                    &input,
                    Some(ID)
                )
                .is_err()
            );
        }
        for field in ["user_id", "saved_revision", "rejection"] {
            let mut body = result("update_user", "saved");
            body.as_object_mut()
                .ok_or_else(|| io::Error::other("fixture object absent"))?
                .remove(field);
            assert!(
                decode(
                    &serde_json::to_vec(&body).map_err(io::Error::other)?,
                    &input,
                    Some(ID)
                )
                .is_err()
            );
        }
        assert!(
            decode(
                &serde_json::to_vec(&result("update_user", "reserved"))
                    .map_err(io::Error::other)?,
                &input,
                Some(ID)
            )
            .is_err()
        );
        assert!(
            decode(
                &serde_json::to_vec(&result("update_user", "saved")).map_err(io::Error::other)?,
                &input,
                None
            )
            .is_err()
        );
        Ok(())
    }

    struct Reply {
        status: u16,
        body: Vec<u8>,
        extra: &'static str,
        partial: bool,
        close: bool,
    }

    impl Reply {
        fn json(status: u16, value: Value) -> io::Result<Self> {
            Ok(Self {
                status,
                body: serde_json::to_vec(&value).map_err(io::Error::other)?,
                extra: "",
                partial: false,
                close: false,
            })
        }
    }

    #[derive(Default)]
    struct Observed {
        connections: AtomicUsize,
        requests: Mutex<Vec<(String, Value)>>,
        extra: AtomicUsize,
        closed: AtomicUsize,
        sent: Notify,
        closure: Notify,
    }

    struct Peer {
        origin: String,
        observed: Arc<Observed>,
    }

    /// The server only records synthetic requests. Every read/write task belongs
    /// to the caller's JoinSet and is joined on either success or ordinary failure.
    async fn peer(
        tasks: &mut JoinSet<io::Result<()>>,
        authority: &Authority,
        reply: Reply,
    ) -> io::Result<Peer> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        // These listeners remain bound in the owned JoinSet, so their ports also
        // distinguish each CreateNew certificate pair within this fixture.
        let config = authority.config(
            &format!("write-peer-{}", address.port()),
            "127.0.0.1",
            b"http/1.1",
        )?;
        let origin = format!("https://{address}");
        let observed = Arc::new(Observed::default());
        let counters = observed.clone();
        tasks.spawn(async move {
        let acceptor=TlsAcceptor::from(config);
        loop {
            let(socket,_)=listener.accept().await?;
            counters.connections.fetch_add(1,Ordering::SeqCst);
            let mut stream=acceptor.accept(socket).await.map_err(io::Error::other)?;
            let mut bytes=Vec::new();
            let mut buffer=[0;1024];
            let header_end=loop {
                let length=stream.read(&mut buffer).await?;
                if length==0 {return Err(io::Error::other("write closed before headers"));}
                bytes.extend_from_slice(&buffer[..length]);
                if bytes.len()>8192 {return Err(io::Error::other("write fixture header overflow"));}
                if let Some(index)=bytes.windows(4).position(|part|part==b"\r\n\r\n") {break index+4;}
            };
            let text=std::str::from_utf8(&bytes[..header_end]).map_err(io::Error::other)?;
            let line=text.lines().next().ok_or_else(||io::Error::other("missing request line"))?.to_owned();
            if !line.starts_with("POST /api/v1/proxy/user-operations") {return Err(io::Error::other("unexpected write method/target"));}
            let headers=text.lines().skip(1).filter_map(|line|line.split_once(':')).collect::<Vec<_>>();
            let auth=headers.iter().filter(|(key,_)|key.eq_ignore_ascii_case("authorization")).map(|(_,value)|value.trim()).collect::<Vec<_>>();
            if auth!=[format!("Bearer {TOKEN}").as_str()] {return Err(io::Error::other("unexpected synthetic authorization"));}
            if headers.iter().filter(|(key,_)|key.eq_ignore_ascii_case("content-type")).map(|(_,value)|value.trim()).collect::<Vec<_>>()!=["application/json"] {return Err(io::Error::other("unexpected JSON content type"));}
            let lengths=headers.iter().filter(|(key,_)|key.eq_ignore_ascii_case("content-length")).map(|(_,value)|value.trim().parse::<usize>()).collect::<Result<Vec<_>,_>>().map_err(io::Error::other)?;
            if lengths.len()!=1 || lengths[0]>MAX_JSON_BYTES || headers.iter().any(|(key,_)|key.eq_ignore_ascii_case("transfer-encoding")) {return Err(io::Error::other("unexpected write framing"));}
            let end=header_end.checked_add(lengths[0]).ok_or_else(||io::Error::other("write fixture overflow"))?;
            while bytes.len()<end {
                let length=stream.read(&mut buffer).await?;
                if length==0 {return Err(io::Error::other("write closed before body"));}
                bytes.extend_from_slice(&buffer[..length]);
            }
            if bytes.len()!=end {return Err(io::Error::other("extra request before response"));}
            let body=serde_json::from_slice(&bytes[header_end..end]).map_err(io::Error::other)?;
            counters.requests.lock().map_err(|_|io::Error::other("fixture lock poisoned"))?.push((line,body));
            let head=format!("HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n{}\r\n",reply.status,reply.body.len(),if reply.close {"close"} else {"keep-alive"},reply.extra);
            stream.write_all(head.as_bytes()).await?;
            stream.write_all(if reply.partial {&reply.body[..reply.body.len().min(1)]} else {&reply.body}).await?;
            stream.flush().await?;
            counters.sent.notify_one();
            if reply.close {stream.shutdown().await?;}
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0)|Err(_)=>break,
                    Ok(length)=>{counters.extra.fetch_add(length,Ordering::SeqCst);}
                }
            }
            counters.closed.fetch_add(1,Ordering::SeqCst);
            counters.closure.notify_one();
        }
    });
        Ok(Peer { origin, observed })
    }

    async fn closed(peer: &Peer) -> io::Result<()> {
        tokio::time::timeout(BUDGET, async {
            while peer.observed.closed.load(Ordering::SeqCst) == 0 {
                peer.observed.closure.notified().await;
            }
        })
        .await
        .map_err(|_| io::Error::other("write connection was not dropped"))
    }

    fn one_post(peer: &Peer, input: &Input, id: Option<&str>) -> io::Result<()> {
        assert_eq!(peer.observed.connections.load(Ordering::SeqCst), 1);
        assert_eq!(peer.observed.extra.load(Ordering::SeqCst), 0);
        let records = peer
            .observed
            .requests
            .lock()
            .map_err(|_| io::Error::other("fixture lock poisoned"))?;
        assert_eq!(records.len(), 1);
        let path = id.map_or_else(
            || "/api/v1/proxy/user-operations".into(),
            |id| format!("/api/v1/proxy/user-operations/{id}/execute"),
        );
        assert_eq!(records[0].0, format!("POST {path} HTTP/1.1"));
        assert_eq!(
            records[0].1,
            serde_json::to_value(input).map_err(io::Error::other)?
        );
        Ok(())
    }

    fn prepared(
        authority: &Authority,
        origin: &str,
        action: &str,
        id: Option<&str>,
        label: &str,
    ) -> io::Result<Prepared> {
        let path = authority.write(
            &format!("{label}.json"),
            &serde_json::to_vec(&change(action)).map_err(io::Error::other)?,
        )?;
        let mut a = args(path);
        a.connection = ConnectionArgs {
            origin: origin.into(),
            ca: authority.ca.clone(),
            header_file: authority.header.clone(),
        };
        prepare(match id {
            Some(id) => Command::Execute {
                change: a,
                id: id.into(),
            },
            None => Command::Reserve(a),
        })
    }

    #[test]
    fn one_post_reserves_or_executes_without_get_prefetch_or_chaining() -> io::Result<()> {
        let authority = Authority::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut tasks = JoinSet::new();
            let outcome = async {
                for (index, action) in [
                    "create_user",
                    "update_user",
                    "set_user_active",
                    "delete_user",
                ]
                .into_iter()
                .enumerate()
                {
                    for (execute, state) in
                        [(false, "reserved"), (true, "saved"), (true, "rejected")]
                    {
                        let id = execute.then_some(ID);
                        let mut reply =
                            Reply::json(if execute { 200 } else { 201 }, result(action, state))?;
                        reply.close = index % 2 == 0;
                        let server = peer(&mut tasks, &authority, reply).await?;
                        let response = request(
                            prepared(
                                &authority,
                                &server.origin,
                                action,
                                id,
                                &format!("success-{index}-{state}"),
                            )?,
                            BUDGET,
                        )
                        .await?;
                        assert_eq!(response.state, state);
                        closed(&server).await?;
                        one_post(&server, &input(action)?, id)?;
                    }
                }
                Ok(())
            }
            .await;
            finish(&mut tasks, outcome).await
        })
    }

    #[test]
    fn redirect_old_server_busy_bad_binding_and_bad_bodies_never_resubmit() -> io::Result<()> {
        let authority = Authority::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut tasks = JoinSet::new();
            let outcome = async {
                for index in 0..8 {
                    let mut reply = Reply::json(201, result("create_user", "reserved"))?;
                    match index {
                        0 => {
                            reply.status = 302;
                            reply.extra = "Location: https://127.0.0.1:1/private\r\n";
                        }
                        1 => {
                            reply.status = 400;
                            reply.body = serde_json::to_vec(
                                &json!({"error":{"code":"invalid_json","detail":PRIVATE}}),
                            )
                            .map_err(io::Error::other)?;
                        }
                        2 => {
                            reply.status = 503;
                            reply.body = serde_json::to_vec(
                                &json!({"error":{"code":"policy_busy","detail":PRIVATE}}),
                            )
                            .map_err(io::Error::other)?;
                        }
                        3 => {
                            reply.body = PRIVATE.as_bytes().to_vec();
                        }
                        4 => {
                            let mut value = result("create_user", "reserved");
                            value["node_id"] = json!(OTHER);
                            reply.body = serde_json::to_vec(&value).map_err(io::Error::other)?;
                        }
                        5 => {
                            reply.status = 200;
                        }
                        6 => {
                            reply.body = vec![b' '; 32 * 1024 + 1];
                        }
                        _ => {
                            reply.extra = "Content-Encoding: gzip\r\n";
                        }
                    }
                    let server = peer(&mut tasks, &authority, reply).await?;
                    let error = failed(
                        request(
                            prepared(
                                &authority,
                                &server.origin,
                                "create_user",
                                None,
                                &format!("failure-{index}"),
                            )?,
                            BUDGET,
                        )
                        .await,
                    )?;
                    assert!(error.to_string().contains("outcome may be unknown"));
                    assert!(error.to_string().contains("do not repeat"));
                    assert!(!error.to_string().contains(TOKEN));
                    assert!(!error.to_string().contains(PRIVATE));
                    closed(&server).await?;
                    one_post(&server, &input("create_user")?, None)?;
                }
                Ok(())
            }
            .await;
            finish(&mut tasks, outcome).await
        })
    }

    #[test]
    fn partial_response_timeout_and_cancellation_drop_the_driver_without_retry() -> io::Result<()> {
        let authority = Authority::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
        let mut tasks=JoinSet::new();
        let outcome=async {
            for cancel in [false,true] {
                let mut reply=Reply::json(200,result("update_user","saved"))?;
                reply.partial=true;
                let server=peer(&mut tasks,&authority,reply).await?;
                let budget=if cancel {BUDGET} else {Duration::from_millis(100)};
                let mut pending=Box::pin(request(prepared(&authority,&server.origin,"update_user",Some(ID),if cancel {"cancel"} else {"timeout"})?,budget));
                tokio::select! {
                    result=&mut pending=>return Err(failed(result).err().unwrap_or_else(||io::Error::other("write completed before partial response"))),
                    ()=server.observed.sent.notified()=>{},
                }
                if cancel {drop(pending);} else {
                    let error=failed(pending.await)?;
                    assert_eq!(error.kind(),io::ErrorKind::TimedOut);
                    assert!(error.to_string().contains("outcome may be unknown"));
                }
                closed(&server).await?;
                one_post(&server,&input("update_user")?,Some(ID))?;
            }
            Ok(())
        }.await;
        finish(&mut tasks,outcome).await
    })
    }

    #[test]
    fn failed_output_does_not_echo_writer_detail_or_claim_no_effect() -> io::Result<()> {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, PRIVATE))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let operation = decode(
            &serde_json::to_vec(&result("create_user", "reserved")).map_err(io::Error::other)?,
            &input("create_user")?,
            None,
        )?;
        let error = failed(write_response(&mut Broken, &operation))?;
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("do not repeat"));
        assert!(!error.to_string().contains(PRIVATE));
        assert!(!error.to_string().contains(TOKEN));
        Ok(())
    }
}
