# TrueCrypt Decrypter

[!CAUTION]
This is a non-production / alpha quality utility application. It has only gone through minimal adhoc testing - use at your own risk and do not rely on it to perform correct decryption in all cases.

This is a quick and dirty tool for decrypting TrueCrypt volumes. It's main purpose is to allow efficient decryption and potential migration of files in these volumes given that TrueCrypt is defunct.

## Limitations/Scope:
- Only supports TrueCrypt containers (not Veracrypt)
- Only supports AES encryption mode
- Only supports outputting a raw disk image (i.e equivalent to the output of `dd`)

## Build instructions:
- `cargo build`

## Usage instructions:
- Run:  
`truecrypt-decrypter [path to encrypted truecrypt container file] [path to decrypted image file]`
- Enter the password for the volume when prompted

## Mounting the resulting image:

The exact instructions are OS specific - some utility scripts are provided:  
- OSX:  
    `.\util\mount_osx.sh [path to decrypted image file]`
- Linux:  
    `.\util\mount_linux.sh [path to decrypted image file] [path to mount point]`

## Resources

Loosely based / inspired by the following:
- https://github.com/allexpert/TrueCrypt-7.1a (original TrueCrypt 7.1a source)
- https://github.com/MichaelSchreier/Rust-ccc
- https://github.com/4144414D/pytruecrypt
