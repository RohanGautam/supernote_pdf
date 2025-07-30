use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

fn get_signature(file_path: &str) -> Result<String> {
    const SIGNATURE_OFFSET: u64 = 4;
    const SIGNATURE_LENGTH: usize = 20;

    // The `?` operator is used here. If `File::open` returns an `Err`, the `?`
    // will immediately stop this function and return that `Err` to the caller.
    // If it returns `Ok(file)`, it unwraps the value and assigns it to `file`.
    let mut file = File::open(file_path)?;

    // Seek to the signature's starting position.
    file.seek(SeekFrom::Start(SIGNATURE_OFFSET))?;

    // Read the signature bytes.
    let mut signature_bytes = vec![0; SIGNATURE_LENGTH];
    file.read_exact(&mut signature_bytes)?;

    // Convert the bytes into a readable string.
    // since it is an anyhow result, "?" can propagate any type of error back in a generic way.
    let signature_string = String::from_utf8(signature_bytes)?;

    Ok(signature_string)
}

fn main() -> Result<()> {
    let file_path = "./data/sample.note";
    println!("Attempting to read signature from: {}", file_path);

    let signature = get_signature(file_path)?;
    println!("File Signature: {}", signature);

    Ok(())
}
