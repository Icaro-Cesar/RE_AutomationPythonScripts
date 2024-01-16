import requests
import time

print('''
 __  __  ______  ______  __  __  _____   ______       ______  __  __  ______ ______  __    __  ______  ______ ______    
/\ \_\ \/\  __ \/\  ___\/\ \_\ \/\  __-./\  == \     /\  __ \/\ \/\ \/\__  _/\  __ \/\ "-./  \/\  __ \/\__  _/\  ___\   
\ \  __ \ \  __ \ \___  \ \  __ \ \ \/\ \ \  __<     \ \  __ \ \ \_\ \/_/\ \\ \ \/\ \ \ \-./\ \ \  __ \/_/\ \\ \  __\   
 \ \_\ \_\ \_\ \_\/\_____\ \_\ \_\ \____-\ \_____\    \ \_\ \_\ \_____\ \ \_\\ \_____\ \_\ \ \_\ \_\ \_\ \ \_\\ \_____\ 
  \/_/\/_/\/_/\/_/\/_____/\/_/\/_/\/____/ \/_____/     \/_/\/_/\/_____/  \/_/ \/_____/\/_/  \/_/\/_/\/_/  \/_/ \/_____/ 
                                                                                                                        
                                                                                                                        
                                by: 0x0d4y
''')

def hash_lookup():
    try:
        while True: 
            hunt_url = 'https://hashdb.openanalysis.net/hunt'
            hash_url = 'https://hashdb.openanalysis.net/hash'
            time.sleep(2)
            
            # Request the user to enter the hashing API values
            hashing_api_input = input("\nEnter hash values (separated by commas, Press Crtl+C to Come Back): ")
            hashing_apis = [int(hash_value, 0) for hash_value in hashing_api_input.split(',')]

            for hashing_api in hashing_apis:
                # Create the payload for the hunt request
                hashdb_req = {"hashes": [hashing_api]}

                # Perform the hunt request
                hunt_req = requests.post(hunt_url, json=hashdb_req)

                # Check if there was a hit in the search
                hits = hunt_req.json()['hits']
                if hits:
                    # Extract the algorithm from the hit
                    algorithm = hits[0]['algorithm']

                    # Resolve the hash with the found algorithm
                    hash_resolve = requests.get(f"{hash_url}/{algorithm}/{hashing_api}")

                    # Extract DLL and API information
                    string_info = hash_resolve.json()['hashes'][0]['string']
                    dll_value = string_info['modules'][0]
                    api_value = string_info['api']

                    # Display the desired information
                    print(f"\nHashing Algorithm: {algorithm}")
                    print(f"DLL: {dll_value}")
                    print(f"API: {api_value}\n")
                else:
                    print(f"\nNo match found for hash {hashing_api}")

    except KeyboardInterrupt:
        pass
    finally:
        time.sleep(1)
        print("\nExiting...\n")
        time.sleep(1)

def hash_algorithm_xor_lookup():
    def scan_hash(algorithm, hash_value, xor_key):
        # Construct the API URL
        url = f'https://hashdb.openanalysis.net/hash/{algorithm}/{hash_value}/{xor_key}'
        
        try:
            # Make a GET request to the API
            response = requests.get(url)

            # Check if the response status code is 200 (OK)
            if response.status_code == 200:
                # Parse the JSON response
                result = response.json()
                
                # Check if 'hashes' key is present and not empty
                if 'hashes' in result and result['hashes']:
                    # Extract information for the first hash in the list
                    hash_info = result['hashes'][0]
                    hash_value = hash_value
                    module_name = hash_info['string']['modules'][0] if 'modules' in hash_info['string'] else 'Unknown'
                    api_info = hash_info.get('string', {}).get('api', 'Unknown')
                    
                    # Print the hash, DLL, and API information on separate lines
                    print(f"Hash: {hash_value}")
                    print(f"DLL: {module_name}")
                    print(f"API: {api_info}")
                    print('')  # Separating lines for better readability
                else:
                    print(f"\nNo information found for hash: {hash_value}")
                    print("")
            else:
                print(f"Failed to scan hash {hash_value}. Status code: {response.status_code}")

        except Exception as e:
            # Handle exceptions and print an error message
            print(f"An error occurred while processing hash {hash_value}: {str(e)}")

    while True:
        try:
            # Replace hashes with your own list of integers
            hashes_input = input("\nEnter hash values (separated by commas): ")
            hashes = [int(x) for x in hashes_input.split(',')]

            # Replace the algorithm and xor_key as needed
            algorithm = input("Enter the algorithm: ")
            xor_key = input("Enter the XOR key: ")

            # Iterate through the list of hashes and call the scan_hash function
            for hash_value in hashes:
                scan_hash(algorithm, hash_value, xor_key)

            user_input = input("Press Enter to do more lookups or type 'exit' to go back to the main menu: ")
            if user_input.lower() == 'exit':
                break

        except ValueError:
            print("Invalid input. Please enter valid hash values.")
        except KeyboardInterrupt:
            break

def main():
    while True:
        print("\nMenu:")
        print("1. Hash Lookup")
        print("2. Hash Algorithm + XOR Key Lookup")
        print("3. Exit")

        choice = input("\nEnter your choice (1/2/3): ")

        if choice == '1':
            hash_lookup()
        elif choice == '2':
            hash_algorithm_xor_lookup()
        elif choice == '3':
            print("\nExiting the program. Goodbye!\n")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
