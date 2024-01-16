# Automation Tools to Reverse Engineering

<p align="center">
  <img src="https://user-images.githubusercontent.com/26800596/168480566-89c9c935-20e3-4745-ba34-0a5a8236489d.png" width="600" height="400">
</p>

In this repository, I will store my scripts that I create to automate some processes during some Reverse Engineering tasks.

Some scripts are just code exercises, the main topic of which is reverse engineering.

## Tools

For now, this repository contains the following tools:

- **hashdb_automated**: Yes, there are plugins for *Binary Ninja*, for *IDA Pro*, which already performs this action. However, thinking about Reverse Engineers who are still starting out, and cannot afford the pro version of *IDA* and *Binary Ninja* (and don't want to depend on ***Ghidra's terrible UI***), this script can save several hours when the analyst encounters **Hashed API** calls. In a new update, I gave the ability to accept several Hashes separated by commas, with the aim of the reverse engineer being able to perform the lookup of several Hashed APIs at once. And I gave a new functionality to the script to perform lookups of Hashed APIs using a specific algorithm and containing an XOR key. You obtain this information during your analysis in the disassembler.
- **iced_conf_extractor**: A python conf extractor, for IcedID malware samples. You must provide the *PE section* where the *key + encrypted* data is store (normally, for IceID family, is store in the .data section), set the length of the key (the first bytes of data encrypted on *PE section* (IcedID family pattern)) and the length of the encrypted data. After that, the script will decrypt the data, using **RC4 algorithm**.
