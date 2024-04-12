import pefile
import capstone
import hashlib
import math
import re

print("""\033[1;93m

 (                                            
 )\ )        *   )                            
(()/( (    ` )  /( (   (      )  (  (     (   
 /(_)))\    ( )(_)))(  )\  ( /(  )\))(   ))\  
(_)) ((_)  (_(_())(()\((_) )(_))((_))\  /((_) 
| _ \| __| |_   _| ((_)(_)((_)_  (()(_)(_))   
|   /| _|    | |  | '_|| |/ _` |/ _` | / -_)  
|_|_\|___|   |_|  |_|  |_|\__,_|\__, | \___|  
                                |___/         

\033[m""")

def calculate_entropy(data):
    entropy = 0
    size = len(data)
    probabilities = [float(data.count(c)) / size for c in set(data)]

    for probability in probabilities:
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy

def import_table(pe):
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"Library: \033[1;33m{entry.dll.decode('utf-8')}\033[m\n")
            for imp in entry.imports:
                if imp.name.decode('utf-8') in ['LoadLibraryExW', 'FreeLibrary','VirtualAlloc','VirtualProtect','VirtualAllocEx','OpenProcess','WriteProcessMemory','CreateRemoteThreat','NtCreateThread','RtlCreateUserThread','SuspendThread','ResumeThreat','NtResumeThread','Process32First','Process32Next','Thread32First','Thread32Next','WaitForSingleObject ']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Process Injection\033[m")
                elif imp.name.decode('utf-8') in ['QueueUserAPC','NtQueueApcThread','KeInitializeAPC']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible APC Injection\033[m")
                elif imp.name.decode('utf-8') in ['NtUnmapViewOfSection','ZwUnmapViewOfSection']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Process Hollowing\033[m")
                elif imp.name.decode('utf-8') in ['CreateTransaction','CreateFileTransaction','NtCreateSection']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!]Possible Process Doppelgänging\033[m")
                elif imp.name.decode('utf-8') in ['WinHttpOpen','WinHttpConnect','WinHttpOpenRequest','WinHttpSendRequest','WinHttpReceiveResponse','WinHttpQueryDataAvailable','WinHttpReadData','HttpOpenRequestA','HttpSendRequestA','HttpSendRequestExA','InternetOpenA','InternetOpenUrlA','InternetReadFile','InternetWriteFile','URLDownloadToFile','URLDownloadToCacheFile','URLOpenBlockingStream','URLOpenStream','accept','bind','connect','Gethostbyname','Inet_addr','recv','send','socket','listen','DnsQuery_A','DnsQueryEx','WNetOpenEnumA','FindFirstUrlCacheEntryA','FindNextUrlCacheEntryA','InternetConnectA','InternetSetOptionA']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Command & Control Communication\033[m")
                elif imp.name.decode('utf-8') in ['Sleep','SleepEx','IsDebuggerPresent','NtQueryInformationProcess','GetTickCount64','GetNativeSystemInfo','GetSystemTime','GetComputerNameA','CreateToolhelp32Snapshot','GetLogicalProcessorInformation','GetLogicalProcessorInformationEx','CheckRemoteDebuggerPresent','GetNativeSystemInfo', 'IsProcessorFeaturePresent']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Anti-Debug Technique Implemented\033[m")
                elif imp.name.decode('utf-8') in ['RegEnumKeyExA','RegEnumValueA','RegQueryInfoKeyA','RegQueryMultipleValuesA','RegQueryValueExA','RegEnumKeyA', 'RegDeleteValueA', 'RegOpenKeyExA', 'RegGetValueA', 'RegDeleteKeyA', 'RegDeleteKeyExA']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Registry Key Manipulation\033[m")
                elif imp.name.decode('utf-8') in ['CreateDirectoryA','CreateFileA','GetTempPathA','WriteFile','CreateFile2']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Dropper Second Stage\033[m")
                elif imp.name.decode('utf-8') in ['ControlService','ControlServiceExA','CreateServiceA','DeleteService','OpenSCManagerA', 'OpenServiceA', 'StartServiceA', 'StartServiceCtrlDispatcherA']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Persistence via Services\033[m")
                elif imp.name.decode('utf-8') in ['CryptGenRandom','CryptAcquireContextA','CryptEncrypt','CryptDecrypt','DecryptFileA', 'CryptProtectData', 'CryptSetKeyParam', 'CryptGetHashParam ']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Impact through Cryptography\033[m")
                elif imp.name.decode('utf-8') in ['GetProcAddress','GetCurrentProcess','GetCurrentProcessId','GetCurrentThreadId']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Process/Thread Enumeration\033[m")
                elif imp.name.decode('utf-8') in ['GetModuleFileNameA','GetModuleHandleW','GetModuleHandleExW','GetModuleFileNameW']:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m \033[1;33m->\033[m \033[1;31m[!] Possible Dynamic API Resolution\033[m")
                else:
                    print(f"\t- \033[1;34m{imp.name.decode('utf-8')}\033[m")
            print("")
    except Exception as e:
        print(f"Error analyzing the Import Table: {e}")

def disassemble_code(data, section_va, encryption_method):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    encryption_instructions = []
    conditional_jump_addresses = []

    encryption_methods = {
        'xor': {'mnemonic': 'xor'},
        'rc4': {'mnemonic': 'cmp', 'op_str': ', 0x100'}
    }

    mnemonic = encryption_methods[encryption_method]['mnemonic']

    for i in md.disasm(data, section_va):
        if i.mnemonic == mnemonic:
            if encryption_method == 'rc4' and not i.op_str.endswith(encryption_methods[encryption_method]['op_str']):
                continue
            encryption_instructions.append(i.address)

        if i.mnemonic.startswith('j'):
            conditional_jump_addresses.append(i.address)

    encryption_with_conditional_jump = []
    for encryption_addr in encryption_instructions:
        for jump_addr in conditional_jump_addresses:
            if abs(encryption_addr - jump_addr) < 10:
                encryption_with_conditional_jump.append(encryption_addr)
                break

    return encryption_with_conditional_jump

def get_function_address(pe, address):
    for section in pe.sections:
        if section.contains_rva(address):
            rva_offset = address - section.VirtualAddress
            return pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + rva_offset
    return None

def print_occurrences(pe, section_name, addresses, encryption_method):
    found_occurrences = False
    current_function_addr = None

    for addr in addresses:
        function_addr = get_function_address(pe, addr)
        if function_addr is not None:
            if current_function_addr != function_addr:
                found_occurrences = True
                print(f"\tPossible {encryption_method.upper()} Operation on -> \033[1;34m0x{function_addr:08X}\033[m")
                current_function_addr = function_addr

    return found_occurrences

def encryption_patterns(file_path, encryption_method):
    try:
        pe = pefile.PE(file_path)
        found_occurrences = False
        current_section_name = None

        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            section_data = section.get_data()

            addresses = disassemble_code(section_data, section.VirtualAddress, encryption_method)

            if addresses and section_name not in (".reloc", ".rdata"):
                found_occurrences = True
                if current_section_name != section_name:
                    print(f"\n\033[1;31m[!] Obfuscated Files or Information [T1027] on {section_name}\033[m\nDescription: \033[1;33mPossible obfuscation pattern identified through the {encryption_method.upper()} operation!\033[m\n")
                    current_section_name = section_name

                found = print_occurrences(pe, section_name, addresses, encryption_method)
                if not found:
                    print(f"\tNo {encryption_method.upper()} patterns found in this section.")

            else:
                pass

        if not found_occurrences:
            print(f"\nNo {encryption_method.upper()} patterns found in any section except .reloc and .rdata.\n")
    except Exception as e:
        print(f"Error analyzing the PE file: {e}")

def detect_pe_type(pe_file):
    try:
        pe = pefile.PE(pe_file)

        if pe.OPTIONAL_HEADER.DllCharacteristics & 0x2000:
            print(f'\t\033[1;33mThe sample is a DLL\033[m')
        else:
            print(f'\t\033[1;33mThe file sample is an executable (.exe)\033[m')
    except pefile.PEFormatError as e:
        print(f"Error analyzing the PE file: {e}")

def main_func(file_path):
    try:
        pe = pefile.PE(file_path)
        print(f"\n\033[1;35mBinary Identification\033[m\n")
        detect_pe_type(file_path)
        print(f"\n\n\033[1;35mEntropy of Artifact Sections\033[m\n")
        for section in pe.sections:
            section_name = section.Name.decode('utf-8').rstrip('\x00')
            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            if entropy >= 6.5:
                print(f"\nPE Section: \033[1;31m{section_name}\033[m\n\tEntropy: \033[1;31m{entropy:.4f}\033[m \033[1;33m[!] Possibly Packed or Encrypted!\033[m")
            else:
                print(f"\nPE Section: \033[1;36m{section_name}\033[m\n\tEntropy: \033[1;36m{entropy:.4f}\033[m")

        print(f"\n\n\033[1;35mArtifact Import Table\033[m\n\n")
        import_table(pe)

    except Exception as e:
        print(f"Error analyzing the PE file: {e}")
def calculate_hash(file_path, algorithm='sha256'):
    with open(file_path, 'rb') as file:
        hash_obj = hashlib.new(algorithm)

        while (chunk := file.read(8192)): 
            hash_obj.update(chunk)

    return print(f"\n\n\033[1;35mArtifact Hash\033[m\n\n\t\033[1;33m{hash_obj.hexdigest()}\033[m\n")

def find_interesting_strings(file_path):
    print(f"\n\n\033[1;35mInteresting Strings\033[m\n")
    with open(file_path, 'rb') as file:
        data = file.read().decode('utf-8', errors='ignore')

    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', data)

    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', data)

    file_extensions = ['.dll', '.exe', '.xml', '.txt', '.ps1', '.bat', '.cmd']
    files = re.findall(r'\b\w+(?:{})\b'.format('|'.join(file_extensions)), data, flags=re.IGNORECASE)

    windows_commands = re.findall(r'\b(?:[a-zA-Z]:\\(?:\w+\\)*\w+\.(?:exe|bat|cmd|ps1))\b', data, flags=re.IGNORECASE)

    if urls:
        print("\n\033[1;33mPossible URLs found:\033[m\n")
        for url in urls:
            print(f"- \033[1;31m{url}\033[m")
    if ips:
        print("\n\033[1;33mPossible IP addresses found:\033[m\n")
        for ip in ips:
            print(f"- \033[1;31m{ip}\033[m")
    if files:
        print("\n\033[1;33mPossible Files found:\033[m\n")
        for file in files:
            print(f"- \033[1;31m{file}\033[m")
    if windows_commands:
        print("\n\033[1;33mPossible Windows commands found:\033[m\n")
        for cmds in windows_commands:
            print(f"- \033[1;31m{cmds}\033[m")
    else:
        print(f"\n\033[1;35mNo more interesting strings found\033[m\n")


def main():
    file_path = input("\n\033[1;35mSample Path: \033[m")
    try:
        calculate_hash(file_path)
        main_func(file_path)
        encryption_patterns(file_path, 'rc4')
        encryption_patterns(file_path, 'xor')
        find_interesting_strings(file_path)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
