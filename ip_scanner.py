"""
IP Address Geolocation & Security Scanner
------------------------------------------
Week 1 : Problem understanding, architecture, and data design (this file is
         that design turned into code).
Week 2 : Core features + processing logic -- fetch, security check,
         connection-type check, map link, and the printed card.
Week 3 : Reliability -- specific error handling for timeouts, no internet,
         bad responses, and missing fields (see fetch_ip_data & safe_field).
Week 4 : Validation -- reject a badly formatted IP before any network call
         (see validate_ip), plus aligned column output.
Week 5 : Final polish -- comments added throughout, README written,
         no logic changed from Week 4.
"""

import urllib.request
import urllib.error
import socket
import json
import ipaddress

HEADERS = {"User-Agent": "Mozilla/5.0 (IP-Scanner-Project)"}
FIELDS = "status,message,country,regionName,city,lat,lon,isp,org,zip,query,mobile,proxy,hosting"
LABEL_WIDTH = 11  # keeps every printed line's colon aligned in the same column


# Checks the IP's format locally (using Python's ipaddress module) before any
# network request is made. Blank input is treated as valid (means self-scan).
def validate_ip(ip):
    """Returns True if ip is empty (self-scan) or a valid IPv4/IPv6 address.
    Returns False for anything malformed, e.g. 999.999.999.999 or random text."""
    if ip == "":
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# Sends the actual request to ip-api.com and returns the parsed JSON reply.
# Any network failure is caught here and re-raised as a clear, specific error.
def fetch_ip_data(ip, timeout=5):
    """Builds the URL, sets the User-Agent, calls urlopen(), returns parsed JSON.
    Raises specific, named errors instead of letting the program crash."""
    base = f"http://ip-api.com/json/{ip}" if ip else "http://ip-api.com/json/"
    url = f"{base}?fields={FIELDS}"
    request = urllib.request.Request(url, headers=HEADERS)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw_data = response.read().decode("utf-8")
    except socket.timeout:
        raise ConnectionError("The request timed out. Check your internet speed and try again.")
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"The server returned an error (HTTP {e.code}).")
    except urllib.error.URLError:
        raise ConnectionError("Could not reach the server. Check your internet connection.")

    try:
        return json.loads(raw_data)
    except json.JSONDecodeError:
        raise ValueError("The server sent a response that could not be understood.")


# Safely reads one field from the API's dictionary. Prevents a missing field
# from printing as blank or None -- shows a clear fallback message instead.
def safe_field(data, key, fallback="Not available"):
    """Returns the field if present, otherwise a safe fallback instead of None."""
    value = data.get(key)
    return value if value not in (None, "") else fallback


# Decides the security label from the API's proxy/hosting flags.
def check_security(is_proxy, is_hosting):
    """proxy / hosting flags -> Secure or Potential VPN/Proxy."""
    return "Potential VPN/Proxy" if (is_proxy or is_hosting) else "Secure"


# Decides the connection-type label from the API's mobile flag.
def get_connection_type(is_mobile):
    """mobile flag -> Cellular Network or Standard Broadband."""
    return "Cellular Network" if is_mobile else "Standard Broadband"


# Builds a clickable Google Maps link from the coordinates.
def generate_map_link(lat, lon):
    """Joins lat and lon into a Google Maps URL. Returns 'Not available' if missing."""
    if lat is None or lon is None:
        return "Not available"
    return f"https://www.google.com/maps?q={lat},{lon}"


# Prints one line of the card with its label padded so every colon lines up.
def print_row(label, value):
    """Prints one aligned row: label padded to LABEL_WIDTH, then ' : ', then value."""
    print(f"{label.ljust(LABEL_WIDTH)}: {value}")


# Pulls everything together and prints the final "Network Identity Card".
# ZIP and Org are only printed when Clean View (privacy mode) is turned off.
def display_card(data, clean_view):
    """Prints the Network Identity Card; hides ZIP and Org if Clean View is on."""
    city = safe_field(data, "city")
    region = safe_field(data, "regionName")
    country = safe_field(data, "country")
    isp = safe_field(data, "isp")
    lat, lon = data.get("lat"), data.get("lon")

    connection = get_connection_type(data.get("mobile"))
    security = check_security(data.get("proxy"), data.get("hosting"))
    map_link = generate_map_link(lat, lon)

    print("\n--- IP SECURITY SCAN ---")
    print_row("IP ADDRESS", safe_field(data, "query"))
    print_row("LOCATION", f"{city}, {region}, {country}")
    print_row("ISP", isp)
    print_row("LAT/LON", f"{lat if lat is not None else 'Not available'}, "
                          f"{lon if lon is not None else 'Not available'}")
    print_row("MAP LINK", map_link)
    print_row("SECURITY", f"{connection} "
                           f"({'No Proxy Detected' if security == 'Secure' else 'Proxy/Hosting Suspected'})")

    if not clean_view:
        print_row("ZIP CODE", safe_field(data, "zip"))
        print_row("ORG", safe_field(data, "org"))


# Entry point: reads user input, validates it, fetches the data, and prints
# the card -- or a clear [ERROR] message if anything along the way fails.
def main():
    try:
        ip = input("Enter IP address (leave blank for your own IP): ").strip()
        clean_view = input("Enable Clean View? (y/n): ").strip().lower() == "y"
    except EOFError:
        print("[ERROR] No input received. Run this program in an interactive terminal.")
        return

    if not validate_ip(ip):
        print("[ERROR] Invalid IP Address format")
        return

    try:
        data = fetch_ip_data(ip)
    except (ConnectionError, ValueError) as e:
        print(f"[ERROR] {e}")
        return

    if data.get("status") == "fail":
        reason = data.get("message", "unknown reason")
        print(f"[ERROR] Invalid IP Address format ({reason})")
        return

    display_card(data, clean_view)


# Only runs main() when this file is executed directly, not when imported.
if __name__ == "__main__":
    main()