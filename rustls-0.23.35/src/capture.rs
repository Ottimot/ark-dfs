use std::{
    fs::OpenOptions,
    io::Write,
    sync::{Mutex, OnceLock},
};

static OUT: OnceLock<Mutex<std::fs::File>> = OnceLock::new();

fn file() -> &'static Mutex<std::fs::File> {
    OUT.get_or_init(|| {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            //.truncate(true)
            .open("handshake_dump.txt")
            .expect("open handshake_dump.txt");
        Mutex::new(f)
    })
}

pub(crate) fn write_hex(label: &str, bytes: &[u8]) {
    let mut f = file().lock().unwrap();
    let _ = writeln!(f, r#"{label}="{}""#, hex::encode(bytes));
    let _ = f.flush();
}
