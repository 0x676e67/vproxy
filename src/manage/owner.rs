//! Node-local offline ownership, authorized by private filesystem access.
//! No remote endpoint, browser identity or password is accepted by these commands.

use std::{
    io::{self, Write},
    path::PathBuf,
};

use clap::Subcommand;

use super::store;

#[derive(Subcommand)]
pub enum Command {
    /// Read this node's current owner and epoch without changing state
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Delegate policy to an enrolled active peer after stopping manage serve
    Grant {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Stable ID already registered on this node; never an IP or administrator ID
        #[arg(long)]
        controller_node_id: String,
        /// Current epoch from owner status; even the same owner advances it
        #[arg(long)]
        expected_epoch: u64,
    },
    /// Restore local policy ownership after stopping manage serve
    Takeover {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        expected_epoch: u64,
    },
}

/// Only status may run alongside serve. Mutations use its author lock and fail
/// immediately if occupied; they never stop a process or retry an uncertain commit.
/// File ownership is explicit authority, not an impersonated Web administrator.
pub(super) fn run(command: Command) -> io::Result<()> {
    let (data_dir, change) = match command {
        Command::Status { data_dir } => (data_dir, None),
        Command::Grant {
            data_dir,
            controller_node_id,
            expected_epoch,
        } => (data_dir, Some((expected_epoch, Some(controller_node_id)))),
        Command::Takeover {
            data_dir,
            expected_epoch,
        } => (data_dir, Some((expected_epoch, None))),
    };
    let directory = super::directory(data_dir)?;
    let overview = store::inspect(&directory)?;
    let owner = match change {
        Some((expected, controller)) => {
            store::set_owner_offline(&directory, expected, controller.as_deref())?
        }
        None => store::ownership(&directory)?,
    };
    let mut output = io::stdout().lock();
    writeln!(output, "node_id={}", overview.node_id)?;
    writeln!(
        output,
        "controller_node_id={}",
        owner.controller_node_id.as_deref().unwrap_or("local")
    )?;
    writeln!(output, "epoch={}", owner.epoch)?;
    writeln!(
        output,
        "last_terminal_command={}",
        owner.last_terminal_command
    )
}
