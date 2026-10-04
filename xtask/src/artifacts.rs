// SPDX-License-Identifier: MIT OR Apache-2.0

pub const MAX_FILES: usize = 2;

pub fn stage_then_read<T, E>(
    files: &[T],
    mut stage: impl FnMut(&T) -> Result<(), E>,
    mut read: impl FnMut(&T) -> Result<(), E>,
) -> Result<(), E> {
    for file in files {
        stage(file)?;
    }
    for file in files {
        read(file)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::stage_then_read;
    use std::fs;

    #[test]
    fn every_artifact_survives_eviction_of_the_finished_workspace() {
        let root = (0..8)
            .find_map(|attempt| {
                let path = std::env::temp_dir()
                    .join(format!("cb-artifacts-{}-{attempt}", std::process::id()));
                match fs::create_dir(&path) {
                    Ok(()) => Some(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("cannot reserve artifact fixture: {error}"),
                }
            })
            .expect("artifact fixture reservation exhausted");
        let worker = root.join("worker");
        let staged = root.join("staged");
        fs::create_dir(&worker).unwrap();
        fs::create_dir(&staged).unwrap();
        let files = ["recovery.json", "proof-bundle.tar.gz"];
        fs::write(worker.join(files[0]), b"verified recovery").unwrap();
        fs::write(worker.join(files[1]), [0, 255, 1, 128]).unwrap();
        let stage = |file: &&str| fs::copy(worker.join(file), staged.join(file)).map(|_| ());
        let read = |file: &&str| {
            if worker.exists() {
                fs::remove_dir_all(&worker)?;
            }
            fs::read(staged.join(file)).map(|_| ())
        };
        stage_then_read(&files, stage, read).unwrap();
        assert_eq!(fs::read(staged.join(files[1])).unwrap(), [0, 255, 1, 128]);

        fs::create_dir(&worker).unwrap();
        fs::write(worker.join(files[0]), b"verified recovery").unwrap();
        fs::write(worker.join(files[1]), [0, 255, 1, 128]).unwrap();
        stage(&files[0]).unwrap();
        read(&files[0]).unwrap();
        assert!(stage(&files[1]).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
