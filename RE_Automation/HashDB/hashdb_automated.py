print('''

 __  __  ______  ______  __  __  _____   ______       ______  __  __  ______ ______  __    __  ______  ______ ______    
/\ \_\ \/\  __ \/\  ___\/\ \_\ \/\  __-./\  == \     /\  __ \/\ \/\ \/\__  _/\  __ \/\ "-./  \/\  __ \/\__  _/\  ___\   
\ \  __ \ \  __ \ \___  \ \  __ \ \ \/\ \ \  __<     \ \  __ \ \ \_\ \/_/\ \\ \ \/\ \ \ \-./\ \ \  __ \/_/\ \\ \  __\   
 \ \_\ \_\ \_\ \_\/\_____\ \_\ \_\ \____-\ \_____\    \ \_\ \_\ \_____\ \ \_\\ \_____\ \_\ \ \_\ \_\ \_\ \ \_\\ \_____\ 
  \/_/\/_/\/_/\/_/\/_____/\/_/\/_/\/____/ \/_____/     \/_/\/_/\/_____/  \/_/ \/_____/\/_/  \/_/\/_/\/_/  \/_/ \/_____/ 
                                                                                                                        
                                                                                                                        
                                    by: 0x0d4y

''')
import requests
import time

try:
    while True: 
        hunt_url = 'https://hashdb.openanalysis.net/hunt'
        hash_url = 'https://hashdb.openanalysis.net/hash'
        time.sleep(2)
        # Request the user to enter the hashing API value
        hashing_api = input("\nEnter the hashing API value (Press Crtl+C to Exit): ")

        # Convert the input to an integer
        hashing_api = int(hashing_api, 0)

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
    print("\nExiting...")
    time.sleep(1)