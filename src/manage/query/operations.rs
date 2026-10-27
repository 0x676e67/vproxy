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

#[cfg(test)]
mod tests {
    //! Fixed read targets, strict public history and one-shot owned HTTPS queries.

    use std::path::PathBuf;

    use serde_json::{Value, json};
    use tokio::task::JoinSet;

    use super::*;
    use crate::manage::query::{
        self,
        tests::{
            A, Authority, B, C, D, NETWORK_BUDGET, PRIVATE_BODY, Reply, TOKEN, finish, one_request,
            peer_at, wait_closed,
        },
    };

    fn connection() -> ConnectionArgs {
        ConnectionArgs {
            origin: "https://127.0.0.1:1".into(),
            ca: PathBuf::from("not-read-by-operation-input-tests.pem"),
            header_file: PathBuf::from("not-read-by-operation-input-tests.header"),
        }
    }

    fn context(node: Option<&str>) -> Command {
        Command::Context(ContextArgs {
            connection: connection(),
            node_id: node.map(str::to_owned),
        })
    }

    fn list(before: Option<&str>, limit: u32) -> Command {
        Command::List(ListArgs {
            connection: connection(),
            node_id: A.into(),
            before: before.map(str::to_owned),
            limit,
        })
    }

    fn get(id: &str, revision: Option<&str>, epoch: Option<&str>) -> Command {
        Command::Get(GetArgs {
            connection: connection(),
            node_id: A.into(),
            id: id.into(),
            expected_revision: revision.map(str::to_owned),
            expected_epoch: epoch.map(str::to_owned),
        })
    }

    fn operation() -> Value {
        json!({
            "id": B, "node_id": A, "sequence": "9", "expected_revision": "7",
            "expected_epoch": "3", "action": "create_user", "user_id": C,
            "state": "saved", "saved_revision": "8", "rejection": null
        })
    }

    fn page(items: Vec<Value>, next: Option<&str>) -> Value {
        json!({"items": items, "next_cursor": next})
    }

    fn decode(read: &Read, value: &Value) -> io::Result<Response> {
        read.decode(&serde_json::to_vec(value).map_err(io::Error::other)?)
    }

    fn public_value(response: Response) -> io::Result<Value> {
        serde_json::to_value(response).map_err(io::Error::other)
    }

    fn failure<T>(result: io::Result<T>) -> io::Result<io::Error> {
        result
            .err()
            .ok_or_else(|| io::Error::other("expected operation query rejection"))
    }

    fn rejected(read: &Read, value: &Value) -> io::Result<()> {
        let error = failure(decode(read, value))?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "inconsistent management operation response"
        );
        assert!(!error.to_string().contains(TOKEN));
        assert!(!error.to_string().contains(PRIVATE_BODY));
        Ok(())
    }

    #[test]
    fn operation_inputs_select_only_fixed_get_targets_and_validate_before_file_access()
    -> io::Result<()> {
        for (command, path) in [
            (context(None), format!("{RESOURCE}/context")),
            (context(Some(A)), format!("{RESOURCE}/context")),
            (list(None, 2), format!("{RESOURCE}?limit=2")),
            (list(Some("10"), 2), format!("{RESOURCE}?limit=2&before=10")),
            (get(B, Some("7"), Some("3")), format!("{RESOURCE}/{B}")),
        ] {
            let (_, read) = Read::from_command(command)?;
            assert_eq!(read.path(), path);
            assert!(!read.path().contains("/execute"));
        }
        for id in [
            "",
            "not-an-id",
            "AAAAAAAAAAAAAAAAAAAAAB",
            "../context",
            "context/execute",
            "a?token=private",
        ] {
            for command in [context(Some(id)), get(id, None, None)] {
                assert_eq!(
                    failure(Read::from_command(command))?.kind(),
                    io::ErrorKind::InvalidInput
                );
            }
            let input = ListArgs {
                connection: connection(),
                node_id: id.into(),
                before: None,
                limit: 2,
            };
            assert_eq!(
                failure(Read::from_command(Command::List(input)))?.kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for value in [
            "",
            "0",
            "01",
            "+1",
            "-1",
            "1&limit=50",
            "9223372036854775808",
        ] {
            for command in [
                list(Some(value), 2),
                get(B, Some(value), None),
                get(B, None, Some(value)),
            ] {
                assert_eq!(
                    failure(Read::from_command(command))?.kind(),
                    io::ErrorKind::InvalidInput
                );
            }
        }
        for limit in [0, 51] {
            assert_eq!(
                failure(Read::from_command(list(None, limit)))?.kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for command in [
            list(Some("9223372036854775807"), 50),
            get(B, None, Some("3")),
            get(B, Some("7"), None),
        ] {
            assert!(Read::from_command(command).is_ok());
        }
        let (mut connection, read) = Read::from_command(context(None))?;
        connection.origin = "http://127.0.0.1".into();
        // Both fixture files are absent. Origin rejection must precede their reads.
        assert_eq!(
            failure(query::prepare_read(
                connection,
                query::Read::Operations(read)
            ))?
            .kind(),
            io::ErrorKind::InvalidInput
        );
        Ok(())
    }

    #[test]
    fn context_and_exact_history_validate_identity_cas_states_and_required_nulls() -> io::Result<()>
    {
        let (_, context_read) = Read::from_command(context(Some(A)))?;
        let value =
            json!({"node_id": A, "policy_revision": "90", "expected_epoch": "4", "local": false});
        assert_eq!(public_value(decode(&context_read, &value)?)?, value);
        for (field, replacement) in [
            ("node_id", json!(B)),
            ("policy_revision", json!("0")),
            ("expected_epoch", json!("01")),
            ("policy_revision", json!(90)),
            ("local", json!("false")),
            ("secret", json!(PRIVATE_BODY)),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement;
            rejected(&context_read, &invalid)?;
        }
        let (_, unbound) = Read::from_command(context(None))?;
        let mut invalid = value.clone();
        invalid["node_id"] = json!("not-an-id");
        rejected(&unbound, &invalid)?;

        let (_, exact) = Read::from_command(get(B, Some("7"), Some("3")))?;
        for action in [
            "create_user",
            "update_user",
            "set_user_active",
            "delete_user",
        ] {
            for state in ["reserved", "saved", "rejected"] {
                let mut valid = operation();
                valid["action"] = json!(action);
                valid["state"] = json!(state);
                if state != "saved" {
                    valid["saved_revision"] = Value::Null;
                    valid["user_id"] = if action == "create_user" {
                        Value::Null
                    } else {
                        json!(C)
                    };
                    if state == "rejected" {
                        valid["rejection"] = json!("policy_conflict");
                    }
                }
                assert_eq!(public_value(decode(&exact, &valid)?)?, valid);
            }
        }
        for (field, replacement) in [
            ("id", json!(C)),
            ("node_id", json!(D)),
            ("sequence", json!("01")),
            ("expected_revision", json!("8")),
            ("expected_epoch", json!("4")),
            ("action", json!("create_credential")),
            ("state", json!("applied")),
            ("user_id", Value::Null),
            ("user_id", json!("not-an-id")),
            ("saved_revision", Value::Null),
            ("saved_revision", json!("7")),
            ("rejection", json!("policy_conflict")),
            ("secret", json!(PRIVATE_BODY)),
        ] {
            let mut invalid = operation();
            invalid[field] = replacement;
            rejected(&exact, &invalid)?;
        }
        let mut reserved = operation();
        reserved["state"] = json!("reserved");
        reserved["user_id"] = Value::Null;
        reserved["saved_revision"] = Value::Null;
        assert_eq!(public_value(decode(&exact, &reserved)?)?, reserved);
        // All three are valid nulls here. Without required_nullable, omission
        // would silently become None and pass the public-state checks too.
        for missing in ["user_id", "saved_revision", "rejection"] {
            let mut invalid = reserved.clone();
            invalid
                .as_object_mut()
                .ok_or_else(|| io::Error::other("fixture object"))?
                .remove(missing);
            rejected(&exact, &invalid)?;
        }
        let (_, unconstrained) = Read::from_command(get(B, None, None))?;
        let mut upper = operation();
        upper["expected_revision"] = json!("9223372036854775806");
        upper["saved_revision"] = json!("9223372036854775807");
        assert_eq!(public_value(decode(&unconstrained, &upper)?)?, upper);
        upper["expected_revision"] = json!("9223372036854775807");
        rejected(&unconstrained, &upper)?;
        for (state, action, user_id, rejection) in [
            ("reserved", "create_user", json!(C), Value::Null),
            ("reserved", "update_user", Value::Null, Value::Null),
            (
                "reserved",
                "create_user",
                Value::Null,
                json!("policy_conflict"),
            ),
            ("rejected", "create_user", Value::Null, Value::Null),
            ("rejected", "create_user", Value::Null, json!(PRIVATE_BODY)),
        ] {
            let mut invalid = operation();
            invalid["state"] = json!(state);
            invalid["action"] = json!(action);
            invalid["user_id"] = user_id;
            invalid["saved_revision"] = Value::Null;
            invalid["rejection"] = rejection;
            rejected(&exact, &invalid)?;
        }
        Ok(())
    }

    #[test]
    fn operation_pages_bind_node_descending_sequence_and_the_original_cursor() -> io::Result<()> {
        let (_, read) = Read::from_command(list(Some("10"), 2))?;
        let first = operation();
        let mut second = operation();
        second["id"] = json!(C);
        second["sequence"] = json!("8");
        let valid = page(vec![first.clone(), second.clone()], Some("8"));
        assert_eq!(public_value(decode(&read, &valid)?)?, valid);
        let mut oldest = second.clone();
        oldest["sequence"] = json!("1");
        let terminal_page = page(vec![first.clone(), oldest.clone()], None);
        assert_eq!(public_value(decode(&read, &terminal_page)?)?, terminal_page);
        // Empty history has no node field to authenticate. It remains an empty
        // observation, not proof that the selected node/caller ever had no writes.
        assert_eq!(
            public_value(decode(&read, &page(Vec::new(), None))?)?,
            page(Vec::new(), None)
        );
        let mut duplicate_id = second.clone();
        duplicate_id["id"] = json!(B);
        let mut duplicate_sequence = second.clone();
        duplicate_sequence["sequence"] = json!("9");
        let mut other_node = second.clone();
        other_node["node_id"] = json!(D);
        let mut at_boundary = first.clone();
        at_boundary["sequence"] = json!("10");
        for invalid in [
            page(vec![second.clone(), first.clone()], None),
            page(vec![first.clone(), duplicate_id], None),
            page(vec![first.clone(), duplicate_sequence], None),
            page(vec![first.clone(), other_node], None),
            page(vec![first.clone(), oldest], Some("1")),
            page(vec![at_boundary], None),
            page(vec![first.clone(), second.clone(), second.clone()], None),
            page(vec![first.clone(), second], Some("7")),
            page(vec![first], Some("9")),
            page(Vec::new(), Some("9")),
            json!({"items": [], "next_cursor": "01"}),
            json!({"items": []}),
            json!({"items": [], "next_cursor": null, "secret": PRIVATE_BODY}),
        ] {
            rejected(&read, &invalid)?;
        }
        Ok(())
    }

    #[test]
    fn real_operation_queries_get_once_without_paging_execution_fallback_or_error_body_leaks()
    -> io::Result<()> {
        let authority = Authority::new()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
        let mut tasks = JoinSet::new();
        let outcome = async {
            let mut older = operation();
            older["id"] = json!(C);
            older["sequence"] = json!("8");
            for (index, (command, wire)) in [
                (context(Some(A)), json!({"node_id": A, "policy_revision": "90", "expected_epoch": "4", "local": false})),
                (list(Some("10"), 2), page(vec![operation(), older], Some("8"))),
                (get(B, Some("7"), Some("3")), operation()),
            ].into_iter().enumerate() {
                let (mut connection, read) = Read::from_command(command)?;
                let path = read.path();
                let server = peer_at(&mut tasks, authority.config(&format!("operation-ok-{index}"), "127.0.0.1", b"http/1.1")?,
                                     Reply::json(wire.clone())?, Some(&path)).await?;
                connection.origin = server.origin.clone();
                connection.ca = authority.ca.clone();
                connection.header_file = authority.header.clone();
                let response = query::request(query::prepare_read(connection, query::Read::Operations(read))?, NETWORK_BUDGET).await?;
                assert_eq!(public_value(response)?, wire);
                wait_closed(&server).await?;
                one_request(&server);
            }
            for (index, status, code, kind, expected) in [
                (0, 403, "insufficient_scope", io::ErrorKind::PermissionDenied, "insufficient_scope"),
                (1, 404, "operation_not_queryable", io::ErrorKind::NotFound, "operation_not_queryable"),
                (2, 503, "management_upgrade_required", io::ErrorKind::WouldBlock, "management_upgrade_required"),
                (3, 500, PRIVATE_BODY, io::ErrorKind::Other, "request_rejected"),
            ] {
                let (mut connection, read) = Read::from_command(get(B, None, None))?;
                let path = read.path();
                let mut reply = Reply::json(json!({"error": {"code": code, "detail": PRIVATE_BODY}, "token": TOKEN}))?;
                reply.status = status;
                let server = peer_at(&mut tasks, authority.config(&format!("operation-error-{index}"), "127.0.0.1", b"http/1.1")?,
                                     reply, Some(&path)).await?;
                connection.origin = server.origin.clone();
                connection.ca = authority.ca.clone();
                connection.header_file = authority.header.clone();
                let error = failure(query::request(query::prepare_read(connection, query::Read::Operations(read))?, NETWORK_BUDGET).await)?;
                assert_eq!(error.kind(), kind);
                assert_eq!(error.to_string(), format!("management query rejected ({status}, {expected})"));
                assert!(!error.to_string().contains(TOKEN));
                assert!(!error.to_string().contains(PRIVATE_BODY));
                wait_closed(&server).await?;
                one_request(&server);
            }
            Ok(())
        }.await;
        finish(&mut tasks, outcome).await
    })
    }
}
