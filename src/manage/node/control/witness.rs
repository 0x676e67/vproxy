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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    fn operation(action: Action) -> Operation {
        Operation {
            enrollment: Enrollment {
                witness_node_id: URL_SAFE_NO_PAD.encode([1_u8; 16]),
                binding_id: URL_SAFE_NO_PAD.encode([2_u8; 16]),
                peer_node_id: URL_SAFE_NO_PAD.encode([3_u8; 16]),
                writer_id: URL_SAFE_NO_PAD.encode([4_u8; 16]),
                baseline: "0".repeat(64),
            },
            action,
        }
    }

    fn transition() -> Transition {
        let e = operation(Action::Inspect).enrollment;
        Transition {
            witness_node_id: e.witness_node_id,
            binding_id: e.binding_id,
            writer_id: e.writer_id,
            sequence: "1".into(),
            previous: e.baseline,
            commitment: "1".repeat(64),
        }
    }

    fn pending() -> Record {
        let input = transition();
        Record {
            enrollment: operation(Action::Inspect).enrollment,
            sequence: input.sequence,
            previous: Some(input.previous),
            commitment: input.commitment,
            phase: Phase::Pending,
            retired: false,
        }
    }

    #[test]
    fn witness_reply_must_match_every_retained_enrollment_and_transition_field() {
        let operation = operation(Action::Reserve(transition()));
        let valid = pending();
        let decode_record = |record: &Record| {
            decode(
                &operation,
                &serde_json::to_vec(record).unwrap(),
                &operation.enrollment.witness_node_id,
            )
        };
        assert!(decode_record(&valid).is_ok());
        for index in 0..10 {
            let mut changed = valid.clone();
            match index {
                0 => changed.enrollment.witness_node_id = URL_SAFE_NO_PAD.encode([5_u8; 16]),
                1 => changed.enrollment.peer_node_id = URL_SAFE_NO_PAD.encode([5_u8; 16]),
                2 => changed.enrollment.binding_id = URL_SAFE_NO_PAD.encode([5_u8; 16]),
                3 => changed.enrollment.writer_id = URL_SAFE_NO_PAD.encode([5_u8; 16]),
                4 => changed.enrollment.baseline = "2".repeat(64),
                5 => changed.sequence = "2".into(),
                6 => changed.previous = Some("2".repeat(64)),
                7 => changed.commitment = "2".repeat(64),
                8 => changed.retired = true,
                _ => changed.sequence = "01".into(),
            }
            assert!(decode_record(&changed).is_err(), "case {index}");
        }
        let confirm = Operation {
            action: Action::Confirm(transition()),
            ..operation
        };
        let bytes = serde_json::to_vec(&valid).unwrap();
        assert!(decode(&confirm, &bytes, &confirm.enrollment.witness_node_id).is_err());
        let mut confirmed = valid;
        confirmed.phase = Phase::Confirmed;
        let bytes = serde_json::to_vec(&confirmed).unwrap();
        assert!(decode(&confirm, &bytes, &confirm.enrollment.witness_node_id).is_ok());
        let reserve = Operation {
            action: Action::Reserve(transition()),
            ..confirm
        };
        assert!(decode(&reserve, &bytes, &reserve.enrollment.witness_node_id).is_ok());
    }

    #[test]
    fn witness_operation_is_fixed_bounded_and_inspect_does_not_create_an_intent() {
        let inspect = operation(Action::Inspect);
        let (method, path, body) = encode(&inspect).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(
            path,
            format!(
                "/node/v1/witness/bindings/{}",
                inspect.enrollment.binding_id
            )
        );
        assert!(body.is_empty());
        let baseline = Record {
            enrollment: inspect.enrollment.clone(),
            sequence: "0".into(),
            previous: None,
            commitment: inspect.enrollment.baseline.clone(),
            phase: Phase::Confirmed,
            retired: false,
        };
        // The generic JSON decoder cannot fabricate a Fetched authorization proof,
        // even when the complete record matches a retained enrollment.
        assert!(
            super::super::client::decode(
                &super::super::Request::Witness(operation(Action::Inspect)),
                &serde_json::to_vec(&baseline).unwrap(),
                &inspect.enrollment.witness_node_id,
                http::StatusCode::OK,
            )
            .is_err()
        );
        assert!(
            decode(
                &inspect,
                &serde_json::to_vec(&baseline).unwrap(),
                &inspect.enrollment.witness_node_id
            )
            .is_ok()
        );
        let mut malformed = baseline.clone();
        malformed.phase = Phase::Pending;
        assert!(malformed.validate().is_err());
        let mut extra = serde_json::to_value(&baseline).unwrap();
        extra["permission"] = true.into();
        assert!(
            decode(
                &inspect,
                &serde_json::to_vec(&extra).unwrap(),
                &inspect.enrollment.witness_node_id
            )
            .is_err()
        );
        assert!(
            decode(
                &inspect,
                &vec![b' '; MAX_RESPONSE_BYTES + 1],
                &inspect.enrollment.witness_node_id
            )
            .is_err()
        );
        let reserve = operation(Action::Reserve(transition()));
        let (method, path, bytes) = encode(&reserve).unwrap();
        assert_eq!(method, Method::POST);
        assert_eq!(path, "/node/v1/witness/reserve");
        assert_eq!(
            serde_json::from_slice::<Transition>(&bytes).unwrap(),
            transition()
        );
        assert!(
            reserve
                .validate(&URL_SAFE_NO_PAD.encode([6_u8; 16]))
                .is_err()
        );
        for index in 0..3 {
            let mut input = transition();
            match index {
                0 => input.witness_node_id = URL_SAFE_NO_PAD.encode([6_u8; 16]),
                1 => input.binding_id = URL_SAFE_NO_PAD.encode([6_u8; 16]),
                _ => input.writer_id = URL_SAFE_NO_PAD.encode([6_u8; 16]),
            }
            assert!(encode(&operation(Action::Reserve(input))).is_err());
        }
    }
}
