import phonenumbers
from phonenumbers import geocoder, carrier, timezone
import whois
import ipaddress
from ipwhois import IPWhois
import socket
import requests
import logging
import json
import subprocess
import os
import time
from scapy.all import IP, ICMP, send

logging.basicConfig(level=logging.INFO)

def phone_lookup(number: str) -> dict:
    try:
        parsed = phonenumbers.parse(number, None)
        if not phonenumbers.is_valid_number(parsed):
            return {"error": "Invalid phone number"}
        return {
            "country": geocoder.description_for_number(parsed, "en"),
            "carrier": carrier.name_for_number(parsed, "en"),
            "timezones": list(timezone.time_zones_for_number(parsed)),
            "type": "mobile" if phonenumbers.number_type(parsed) == phonenumbers.PhoneNumberType.MOBILE else "fixed_line"
        }
    except Exception as e:
        return {"error": str(e)}

def get_ip_from_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def ip_lookup(query: str) -> dict:
    # query can be IP or domain
    try:
        ipaddress.ip_address(query)  # check if valid IP
        ip = query
    except ValueError:
        ip = get_ip_from_domain(query)
        if not ip:
            return {"error": "Could not resolve domain"}

    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        network = res.get('network', {})
        return {
            "ip": ip,
            "country": network.get('country', 'N/A'),
            "organization": network.get('name', 'N/A'),
            "cidr": network.get('cidr', 'N/A'),
            "asn": res.get('asn', 'N/A'),
            "asn_description": res.get('asn_description', 'N/A')
        }
    except Exception as e:
        return {"error": str(e)}

def mac_lookup(mac: str) -> dict:
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url)
        if response.status_code == 200:
            return {"vendor": response.text.strip()}
        else:
            return {"error": "MAC vendor not found"}
    except Exception as e:
        return {"error": str(e)}

def generate_search_links(image_url: str) -> dict:
    from urllib.parse import quote
    return {
        "Google": f"https://www.google.com/searchbyimage?&image_url={quote(image_url)}",
        "Google Lens": f"https://lens.google.com/uploadbyurl?url={quote(image_url)}",
        "Yandex": f"https://yandex.com/images/search?rpt=imageview&url={quote(image_url)}",
        "TinEye": f"https://www.tineye.com/search/?url={quote(image_url)}"
    }

def breach_lookup(query: str) -> dict:
    try:
        url = f"https://api.proxynova.com/comb?query={query}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return {
                "count": data.get("count", 0),
                "lines": data.get("lines", [])
            }
        else:
            return {"error": "Breach lookup failed"}
    except Exception as e:
        return {"error": str(e)}

def extract_metadata(file_path: str) -> dict:
    try:
        # Using exiftool via subprocess
        result = subprocess.run(
            ['exiftool', '-j', file_path],
            capture_output=True,
            text=True,
            check=True
        )
        metadata = json.loads(result.stdout)[0]
        return metadata
    except Exception as e:
        return {"error": str(e)}

def stress_test(target: str, duration: int):
    # Returns a generator to stream progress
    start_time = time.time()
    packets_sent = 0
    try:
        while time.time() - start_time < duration:
            packet = IP(dst=target)/ICMP()
            send(packet, verbose=False)
            packets_sent += 1
            yield f"Packets sent: {packets_sent}"
    except Exception as e:
        yield f"Error: {str(e)}"
    finally:
        yield f"Completed. Total packets: {packets_sent}"