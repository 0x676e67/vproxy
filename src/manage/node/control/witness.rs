//! Typed witness operations over the existing bounded node-mTLS transport.
//! Responses must match caller-retained enrollment and the original transition;
//! remote JSON cannot select a source, witness, writer or replacement operation.

use super::Method;
use crate::manage::witness::{Enrollment, Phase, Record, Transition};
use std::io;

pub(super) const MAX_RESPONSE_BYTES: usize = 4096;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// The same enrollment is supplied for inspection and mutation, so a valid
/// record for an old writer/baseline cannot silently satisfy a new caller.
pub(in crate::manage) struct Operation {
    pub(in crate::manage) enrollment: Enrollment,
    pub(in crate::manage) action: Action,
}

/// A retry retains the entire Transition, not just its sequence. Inspect never
/// reserves or confirms anything; callers decide what the observed phase means.
pub(in crate::manage) enum Action {
    Inspect,
    Reserve(Transition),
    Confirm(Transition),
}

impl Operation {
    /// Reject malformed or cross-target input before DNS, TLS or HTTP. The
    /// caller separately binds peer_node_id to its actual local source identity.
    pub(in crate::manage) fn validate(&self, expected_witness: &str) -> io::Result<()> {
        self.enrollment.validate()?;
        if self.enrollment.witness_node_id != expected_witness {
            return Err(invalid("witness differs from the selected endpoint"));
        }
        if let Action::Reserve(input) | Action::Confirm(input) = &self.action {
            input.validate()?;
            if input.witness_node_id != expected_witness
                || input.binding_id != self.enrollment.binding_id
                || input.writer_id != self.enrollment.writer_id
            {
                return Err(invalid("transition differs from the retained enrollment"));
            }
        }
        Ok(())
    }
}

pub(super) fn encode(operation: &Operation) -> io::Result<(Method, String, Vec<u8>)> {
    operation.validate(&operation.enrollment.witness_node_id)?;
    let (path, input) = match &operation.action {
        Action::Inspect => {
            return Ok((
                Method::GET,
                format!(
                    "/node/v1/witness/bindings/{}",
                    operation.enrollment.binding_id
                ),
                Vec::new(),
            ));
        }
        Action::Reserve(input) => ("/node/v1/witness/reserve", input),
        Action::Confirm(input) => ("/node/v1/witness/confirm", input),
    };
    let bytes =
        serde_json::to_vec(input).map_err(|_| invalid("cannot encode witness transition"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(invalid("witness transition exceeds its size limit"));
    }
    Ok((Method::POST, path.into(), bytes))
}

/// Inspect may observe Pending or Confirmed but never a retired/rebound record.
/// Reserve accepts an already-confirmed exact retry; Confirm must acknowledge
/// Confirmed. None of these responses independently prove source durability.
pub(super) fn decode(
    operation: &Operation,
    bytes: &[u8],
    expected_witness: &str,
) -> io::Result<Record> {
    operation.validate(expected_witness)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(invalid("witness response exceeds its size limit"));
    }
    let record: Record =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid witness response"))?;
    record
        .validate()
        .map_err(|_| invalid("invalid witness record"))?;
    if record.retired || record.enrollment != operation.enrollment {
        return Err(invalid(
            "witness response differs from the retained enrollment",
        ));
    }
    if let Action::Reserve(input) | Action::Confirm(input) = &operation.action {
        if record.sequence != input.sequence
            || record.previous.as_ref() != Some(&input.previous)
            || record.commitment != input.commitment
        {
            return Err(invalid(
                "witness response differs from the original transition",
            ));
        }
        if matches!(operation.action, Action::Confirm(_)) && record.phase != Phase::Confirmed {
            return Err(invalid("witness did not confirm the original transition"));
        }
    }
    Ok(record)
}
