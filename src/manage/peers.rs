//! Explicit local node authorization operations. These commands do not contact
//! a remote node except for the separately TLS-verified identity probe.

use std::{
    io::{self, Write},
    path::PathBuf,
};

use clap::{Args, Subcommand};

use super::{node, store, tls};

/// Node registrations are independent of administrator and proxy credentials.
/// Import public certificates only; CA and node private keys never enter SQLite.
#[derive(Subcommand)]
pub enum Command {
    /// List durable registrations, including inactive peers and certificate counts
    List {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Register a peer or add/rotate its public certificate with an expected revision
    Register {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Stable ID obtained through a trusted channel, not inferred from its name
        #[arg(long)]
        node_id: String,
        #[arg(long)]
        name: String,
        /// Explicit CA roots for chain and certificate-purpose validation
        #[arg(long)]
        ca: PathBuf,
        /// Public PEM certificate chain, leaf first; no private key
        #[arg(long)]
        certificate: PathBuf,
        /// Trusted DNS/IP reference name covered by the certificate's SAN
        #[arg(long)]
        server_name: String,
        /// Omit for a new peer; required for all changes to an existing peer
        #[arg(long)]
        expected_revision: Option<u64>,
    },
    /// Disable a peer without forgetting certificates or permanent revocations
    Disable(RevisionArgs),
    /// Enable a peer; permanently revoked certificates remain unusable
    Enable(RevisionArgs),
    /// Permanently revoke an exact certificate, including one that has expired
    Revoke {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Public PEM chain whose first certificate identifies the registration
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        expected_revision: u64,
    },
    /// Verify a registered peer over mTLS before reading its node identity
    Probe(node::ProbeArgs),
}

/// A local authorization mutation requires an explicit current revision; it
/// cannot silently overwrite a concurrent change or resurrect a certificate.
#[derive(Args)]
pub struct RevisionArgs {
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long)]
    node_id: String,
    #[arg(long)]
    expected_revision: u64,
}

/// Run synchronous offline operations on the CLI thread. Only `Probe` starts
/// its own bounded runtime; no management listener or proxy worker is started.
pub(super) fn run(command: Command) -> io::Result<()> {
    let peer = match command {
        Command::List { data_dir } => {
            let peers = store::list_peers(&super::directory(data_dir)?)?;
            let mut output = io::stdout().lock();
            for peer in peers {
                write_peer(&mut output, &peer)?;
            }
            return Ok(());
        }
        Command::Register {
            data_dir,
            node_id,
            name,
            ca,
            certificate,
            server_name,
            expected_revision,
        } => {
            let der = tls::load_peer_certificate(&ca, &certificate, &server_name)?;
            store::register_peer(
                &super::directory(data_dir)?,
                &node_id,
                &name,
                &der,
                &server_name,
                expected_revision,
            )?
        }
        Command::Disable(args) => set_active(args, false)?,
        Command::Enable(args) => set_active(args, true)?,
        Command::Revoke {
            data_dir,
            certificate,
            expected_revision,
        } => {
            // Expiration does not erase authorization history. Decoding this
            // public leaf is not a new trust decision or a date-validity check.
            let der = tls::read_certificate_leaf(&certificate)?;
            store::revoke_certificate(&super::directory(data_dir)?, &der, expected_revision)?
        }
        Command::Probe(args) => return node::probe(args),
    };
    write_peer(&mut io::stdout().lock(), &peer)
}

fn set_active(args: RevisionArgs, active: bool) -> io::Result<store::PeerSummary> {
    store::set_peer_active(
        &super::directory(args.data_dir)?,
        &args.node_id,
        args.expected_revision,
        active,
    )
}

/// Names are store-validated single lines. Public certificates, passwords and
/// SQL diagnostics are deliberately absent from command output.
fn write_peer(output: &mut impl Write, peer: &store::PeerSummary) -> io::Result<()> {
    writeln!(
        output,
        "node_id={} name={} active={} authorization_revision={} certificates={}",
        peer.node_id, peer.name, peer.active, peer.authorization_revision, peer.certificate_count
    )
}
