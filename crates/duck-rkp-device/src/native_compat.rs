//! Bounded native compatibility choices, made before submitting any CSR to a server.

use anyhow::{Result, anyhow};
use clap::ValueEnum;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BufferMode {
    Raw,
    Shared,
}

impl BufferMode {
    pub(crate) fn argument(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Shared => "shared",
        }
    }
}

/// Stop at the first locally valid CSR. Preserve the primary error code and every
/// variant's reason if all fail; no server operation belongs inside this function.
pub(crate) fn try_variants<T, M: Copy>(
    variants: &[(M, &'static str)],
    mut attempt: impl FnMut(M) -> Result<T>,
) -> Result<T> {
    let mut first = None;
    let mut failures = Vec::new();
    for &(mode, label) in variants {
        match attempt(mode) {
            Ok(value) => return Ok(value),
            Err(error) => {
                failures.push(format!(
                    "{label} [{}]: {error:#}",
                    crate::error::code_of(&error)
                ));
                if first.is_none() {
                    first = Some(error);
                }
            }
        }
    }
    Err(first
        .unwrap_or_else(|| anyhow!("no native variants available"))
        .context(format!(
            "native compatibility attempts failed: {}",
            failures.join("; ")
        )))
}

/// The observed init/sendCmd ABI returns a reply inside the same vendor-owned
/// buffer, beyond the request. Check integer ranges before dereferencing its pointer.
#[cfg(any(test, all(target_os = "android", target_arch = "aarch64")))]
pub(crate) fn shared_reply_in_bounds(
    start: usize,
    capacity: usize,
    request_len: usize,
    reply: usize,
    length: usize,
) -> bool {
    if start == 0
        || request_len == 0
        || capacity > crate::protocol::BUFFER_SIZE
        || request_len > capacity
        || length == 0
    {
        return false;
    }
    let Some(end) = start.checked_add(capacity) else {
        return false;
    };
    let Some(request_end) = start.checked_add(request_len) else {
        return false;
    };
    let Some(reply_end) = reply.checked_add(length) else {
        return false;
    };
    reply >= request_end && reply_end <= end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DeviceRkpError;

    #[test]
    fn stops_at_the_first_success_and_preserves_all_failures_when_exhausted() {
        let variants = [
            (0, "vendor/raw"),
            (1, "vendor/shared"),
            (2, "canonical/raw"),
            (3, "canonical/shared"),
        ];
        for successful in 0..4 {
            let mut calls = Vec::new();
            let result = try_variants(&variants, |mode| {
                calls.push(mode);
                if mode == successful {
                    Ok(mode)
                } else {
                    Err(DeviceRkpError::Rejected(-20).into())
                }
            })
            .unwrap();
            assert_eq!(result, successful);
            assert_eq!(calls, (0..=successful).collect::<Vec<_>>());
        }
        let error = try_variants::<(), _>(&variants, |_| Err(DeviceRkpError::Rejected(-20).into()))
            .unwrap_err();
        assert_eq!(crate::error::code_of(&error), "ta_rejected");
        for (_, label) in variants {
            assert!(format!("{error:#}").contains(label));
        }
    }

    #[test]
    fn shared_reply_rejects_null_overlapping_oversized_and_wrapping_ranges() {
        assert!(shared_reply_in_bounds(1000, 100, 20, 1028, 72));
        for (start, capacity, request, reply, length) in [
            (0, 100, 20, 28, 72),
            (1000, 100, 0, 1028, 72),
            (1000, 100, 101, 1101, 1),
            (1000, 100, 20, 1019, 1),
            (1000, 100, 20, 1028, 73),
            (1000, 100, 20, 1028, 0),
            (usize::MAX - 10, 100, 20, 1, 1),
            (1000, 100, 20, usize::MAX, 2),
            (1000, crate::protocol::BUFFER_SIZE + 1, 20, 1028, 1),
        ] {
            assert!(!shared_reply_in_bounds(
                start, capacity, request, reply, length
            ));
        }
    }
}
