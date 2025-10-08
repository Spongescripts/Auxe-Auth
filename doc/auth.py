import requests
import sys
import uuid  # Example for generating HWID; replace with your HWID method if needed

def get_hwid():
    """
    Generate a simple HWID based on machine UUID. 
    You can use more robust methods (e.g., combining CPU ID, MAC address).
    """
    return str(uuid.getnode())

def aerial_auth(key, server_url='https://your-aerial-domain.com/api/authenticate'):
    """
    Authenticate with Aerial server.
    :param key: The user's license key.
    :param server_url: Your deployed Flask server URL.
    :return: True if successful, False otherwise.
    """
    hwid = get_hwid()
    try:
        response = requests.post(server_url, json={'key': key, 'hwid': hwid}, timeout=5)
        data = response.json()
        if data.get('success'):
            print("Authentication successful!")
            return True
        else:
            print(f"Authentication failed: {data.get('message', 'Unknown error')}")
            return False
    except requests.RequestException as e:
        print(f"Error connecting to auth server: {e}")
        return False

# Example Usage in Your Script
USER_KEY = "paste-your-key-here"  # Or prompt/input the key

if not aerial_auth(USER_KEY):
    print("Exiting due to auth failure.")
    sys.exit(1)

# Your protected code here...
print("Running protected content...")
