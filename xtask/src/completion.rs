// SPDX-License-Identifier: MIT OR Apache-2.0

pub fn persist<E>(
    results: [Result<(), E>; 4],
    record: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    record()?;
    for result in results {
        result?;
    }
    Ok(())
}
