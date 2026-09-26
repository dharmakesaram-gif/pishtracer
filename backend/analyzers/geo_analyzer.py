import os
import socket
from typing import Dict, Any
import geoip2.database
from geoip2.errors import AddressNotFoundError

from config import GEOIP_DB_PATH

class GeoAnalyzer:
    VPN_ASNS = ['NordVPN', 'ExpressVPN', 'Private Internet Access']
    TOR_NODES = ['185.220.101.1', '185.220.101.2'] # Example demo list
    DC_ASNS = ['AMAZON', 'GOOGLE', 'MICROSOFT', 'DIGITALOCEAN', 'OVH', 'HETZNER']

    async def analyze(self, ip: str) -> Dict[str, Any]:
        """
        Analyze IP for geographic location and infrastructure type.
        """
        result = {
            'ip': ip,
            'country': None,
            'country_code': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'asn': None,
            'asn_org': None,
            'infra_type': 'UNKNOWN',
            'risk_flags': [],
            'reverse_dns': None
        }

        if not ip:
            return result

        try:
            orig_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            result['reverse_dns'] = socket.getfqdn(ip)
            socket.setdefaulttimeout(orig_timeout)
        except Exception:
            pass

        # Demo mode / Mock if DB not found
        if not os.path.exists(GEOIP_DB_PATH):
            return self._demo_mode(result, ip)

        try:
            with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
                response = reader.city(ip)
                result['country'] = response.country.name
                result['country_code'] = response.country.iso_code
                result['city'] = response.city.name
                result['latitude'] = response.location.latitude
                result['longitude'] = response.location.longitude
                
                # In a real app, ASN lookup uses a separate GeoLite2-ASN DB
                # Mocking ASN info for this example
                result['asn_org'] = "Mocked ISP"
        except AddressNotFoundError:
            pass
        except Exception as e:
            result['risk_flags'].append(f"GeoIP Error: {str(e)}")

        return self._determine_infra(result)

    def _determine_infra(self, result: Dict[str, Any]) -> Dict[str, Any]:
        if result['ip'] in self.TOR_NODES:
            result['infra_type'] = 'TOR'
            result['risk_flags'].append("IP is a known Tor exit node")
            return result

        org = (result['asn_org'] or "").upper()
        
        if any(vpn.upper() in org for vpn in self.VPN_ASNS):
            result['infra_type'] = 'VPN'
            result['risk_flags'].append("IP belongs to a known VPN provider")
        elif any(dc in org for dc in self.DC_ASNS):
            result['infra_type'] = 'DATACENTER'
            result['risk_flags'].append("Email originating from Datacenter/Cloud IP")
        else:
            result['infra_type'] = 'RESIDENTIAL'

        return result
        
    def _demo_mode(self, result: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Provide realistic mock data when GeoIP DB is missing for demo purposes."""
        # Mock some deterministic behavior based on the last octet
        try:
            last_octet = int(ip.split('.')[-1])
        except:
            last_octet = 0
            
        if last_octet % 3 == 0:
            result.update({
                'country': 'United States', 'country_code': 'US', 'city': 'Ashburn',
                'latitude': 39.0438, 'longitude': -77.4874, 'asn_org': 'AMAZON-02'
            })
        elif last_octet % 3 == 1:
            result.update({
                'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow',
                'latitude': 55.7558, 'longitude': 37.6173, 'asn_org': 'NordVPN'
            })
        else:
            result.update({
                'country': 'India', 'country_code': 'IN', 'city': 'Mumbai',
                'latitude': 19.0760, 'longitude': 72.8777, 'asn_org': 'Reliance Jio'
            })
            
        return self._determine_infra(result)
