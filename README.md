# Windows-Ransomeware
Examples of Windows ransomware

By default, Encryptor will encrypt a copy of all files in a directory passed as argument to the command line. I've included a more destructive function, which will encrypt the actual file, not a copy of its bytes. However, this latter function is not enabled by default. Be sure you know what you're doing if you decide to try it out.

The Decryptor will decrypt all the resulting ".enc" files created by the Encryptor. **Take note of the AES key and IV** (because the default behavior is that you will not be able to determine them again) when you use the Encryptor and compile it with the Decryptor. The reason the two are seperate is to imitate how ransomeware operates, which is to first encrypt sensitive files, leave notice to the victim, then the decryptor is sold to the victim separately.

## Diclaimer
This project is intended for research, demonstrative and educational purposes only. I'm not liable for how you use it.