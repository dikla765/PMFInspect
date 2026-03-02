import netifaces
import subprocess
import re


class NetworkInfo:
    """
    Utility class to extract information from the active Wi-Fi interface:
    IP address, MAC address, and default gateway.
    """

    @staticmethod
    def get_gateway_mac(gateway_ip: str) -> str:
        """
        Retrieve the MAC address of the gateway using ARP.

        Args:
            gateway_ip (str): The IP address of the default gateway.

        Returns:
            str: The gateway MAC address if found, otherwise an empty string.
        """
        try:
            result = subprocess.run(['arp', '-n', gateway_ip], capture_output=True, text=True)
            match = re.search(r'(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})', result.stdout)
            if match:
                return match.group(0)
        except Exception:
            pass
        return ""

    @staticmethod
    def get_wireless_interface_details() -> dict:
        """
        Detect the first active wireless interface and return its details.

        Returns:
            dict: {
                "interface": interface name,
                "ip_address": local IPv4 address,
                "mac_address": local MAC address,
                "gateway_ip": default gateway IP,
                "gateway_mac": default gateway MAC
            }
        """
        wireless_keywords = ["wlan", "wifi", "wl"]

        for interface in netifaces.interfaces():
            if any(keyword in interface.lower() for keyword in wireless_keywords):
                try:
                    iface_addrs = netifaces.ifaddresses(interface)
                    ip_addr = iface_addrs.get(netifaces.AF_INET, [{}])[0].get('addr', '0.0.0.0')
                    mac_addr = iface_addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
                    gateways = netifaces.gateways()
                    gateway_ip = gateways.get('default', {}).get(netifaces.AF_INET, [None])[0] or ''
                    gateway_mac = NetworkInfo.get_gateway_mac(gateway_ip) if gateway_ip else ''
                    
                    return {
                        "interface": interface,
                        "ip_address": ip_addr,
                        "mac_address": mac_addr,
                        "gateway_ip": gateway_ip,
                        "gateway_mac": gateway_mac
                    }
                except Exception:
                    continue

        return {
            "interface": "",
            "ip_address": "0.0.0.0",
            "mac_address": "",
            "gateway_ip": "",
            "gateway_mac": ""
        }


class AllInterfacesInfo:
    """
    Returns all detected Wi-Fi interfaces, whether active or not.
    """

    @staticmethod
    def list_all_wifi_interfaces() -> list:
        """
        Return a list of all network interfaces whose name contains
        wlan, wl, or wifi — which typically indicates a wireless interface.

        Returns:
            list: List of detected Wi-Fi interface names.
        """
        wireless_keywords = ["wlan", "wifi", "wl"]
        return [
            iface for iface in netifaces.interfaces()
            if any(keyword in iface.lower() for keyword in wireless_keywords)
        ]
