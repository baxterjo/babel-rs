//! Shared rendering for the crate's fixed-width identifiers.

/// Formats a right-aligned 8-byte identifier for display.
///
/// [`RouterId`](crate::data_types::RouterId) and
/// [`InterfaceHandle`](crate::data_structures::interface::InterfaceHandle) are both 8-byte arrays
/// holding a right-aligned short name, so they render identically: the name on its own when every
/// significant byte is printable ASCII, and a hex dump of the full eight bytes otherwise.
pub(crate) fn fmt_short_id(id: &[u8; 8], f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    let start = id.iter().position(|&b| b != 0).unwrap_or(id.len());
    let trimmed = &id[start..];

    if trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
        // Known to be displayable due to the check above.
        return f.write_str(core::str::from_utf8(trimmed).unwrap_or(""));
    }

    // Unlike the printable case, the hex form shows all eight bytes including leading padding,
    // since there is no readable name to isolate.
    for (idx, b) in id.iter().enumerate() {
        if idx != id.len() - 1 {
            write!(f, "x{:02X} ", b)?;
        } else {
            write!(f, "x{:02X}", b)?;
        }
    }
    Ok(())
}
