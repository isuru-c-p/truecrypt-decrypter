use clap::Parser;
use std::io::Error;
mod truecrypt;

#[derive(Parser, Debug)]
struct CommandOpts {
    input_path: std::path::PathBuf,
    output_path: std::path::PathBuf
}

fn main() -> Result<(), Error> {
    let opts = CommandOpts::parse();
    let abs_input_path = std::path::absolute(opts.input_path).unwrap();
    let abs_input_path = abs_input_path.to_str().unwrap();
    println!("Opening: {abs_input_path}...");
    println!("Enter password: ");
    let password = rpassword::read_password().unwrap();
    let mut container = truecrypt::TrueCryptContainer::open(&abs_input_path, &password)?;
    let abs_output_path = std::path::absolute(opts.output_path).unwrap();
    let abs_output_path = abs_output_path.to_str().unwrap();
    println!("Decrypting to {}...", abs_output_path);
    let mut output_file = std::fs::File::create(abs_output_path)?;
    container.decrypt(&mut output_file)?;
    return Ok(());
}
