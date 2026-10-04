// SPDX-License-Identifier: MIT OR Apache-2.0

pub trait Backend {
    type Error;
    fn acquire(&self) -> Result<(), Self::Error>;
    fn release(&self);
}

pub struct Lease<B: Backend> {
    backend: B,
}

impl<B: Backend> Lease<B> {
    pub fn acquire(backend: B) -> Result<Self, B::Error> {
        backend.acquire()?;
        Ok(Self { backend })
    }
}

impl<B: Backend> Drop for Lease<B> {
    fn drop(&mut self) {
        self.backend.release();
    }
}

#[cfg(not(kani))]
impl Backend for std::fs::File {
    type Error = std::fs::TryLockError;

    fn acquire(&self) -> Result<(), Self::Error> {
        self.try_lock()
    }

    fn release(&self) {
        if let Err(error) = self.unlock() {
            eprintln!("failed to release the operation lock: {error}");
        }
    }
}

#[cfg(not(kani))]
pub type HeldFile = Lease<std::fs::File>;

#[cfg(not(kani))]
pub fn file(path: &std::path::Path) -> std::io::Result<HeldFile> {
    let file = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    Lease::acquire(file).map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserve_path(nonce: u128) -> std::path::PathBuf {
        for attempt in 0..8 {
            let path = std::env::temp_dir()
                .join(format!("cb-lease-{}-{nonce}-{attempt}", std::process::id()));
            match std::fs::File::options()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot reserve a test file: {error}"),
            }
        }
        panic!("test file reservation exhausted its collision bound");
    }

    fn temporary_path() -> std::path::PathBuf {
        reserve_path(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
    }

    #[test]
    fn reservations_remain_distinct_when_clock_readings_repeat() {
        let first = reserve_path(0);
        let second = reserve_path(0);
        assert_ne!(first, second);
        let first_owner = file(&first).unwrap();
        let second_owner = file(&second).unwrap();
        drop((first_owner, second_owner));
        std::fs::remove_file(first).unwrap();
        std::fs::remove_file(second).unwrap();
    }

    #[test]
    fn dropping_the_owner_unlocks_even_while_an_inherited_handle_remains() {
        let path = temporary_path();
        let owner = file(&path).unwrap();
        let inherited = owner.backend.try_clone().unwrap();
        assert!(file(&path).is_err());
        drop(owner);
        let next = file(&path).unwrap();
        assert!(file(&path).is_err());
        drop(next);
        drop(inherited);
        drop(file(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn another_process_observes_ownership_and_release_with_a_cloned_handle() {
        if let Some(path) = std::env::var_os("CB_LEASE_PROBE_PATH") {
            match std::env::var("CB_LEASE_PROBE_STATE").unwrap().as_str() {
                "held" => match file(std::path::Path::new(&path)) {
                    Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
                    Ok(_) => panic!("another process acquired an owned lock"),
                },
                "released" => drop(file(std::path::Path::new(&path)).unwrap()),
                _ => panic!("unknown lease probe state"),
            }
            println!("CB_LEASE_PROBE_COMPLETED");
            return;
        }
        let path = temporary_path();
        let owner = file(&path).unwrap();
        let inherited = owner.backend.try_clone().unwrap();
        let qualified = concat!(
            module_path!(),
            "::another_process_observes_ownership_and_release_with_a_cloned_handle"
        );
        let (_, name) = qualified.split_once("::").unwrap();
        let observe = |state| {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", name, "--nocapture"])
                .env("CB_LEASE_PROBE_PATH", &path)
                .env("CB_LEASE_PROBE_STATE", state)
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(output.status.success(), "{stdout}");
            assert!(stdout.contains("CB_LEASE_PROBE_COMPLETED"), "{stdout}");
        };
        observe("held");
        drop(owner);
        observe("released");
        drop(inherited);
        drop(file(&path).unwrap());
        std::fs::remove_file(path).unwrap();
    }
}
