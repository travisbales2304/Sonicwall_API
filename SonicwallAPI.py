import requests
import json
from typing import Any, Dict, Optional, List, Union
import urllib3
import re


class SonicwallAPIError(Exception):
    """Custom exception for Sonicwall API errors."""
    pass


class SonicwallAPI:
    """
    Python client for SonicWall API.
    """
    def __init__(
        self,
        host: str,
        port: Union[str, int],
        username: str,
        password: str,
        verify_ssl: bool = False
    ):
        """
        Initialize the API client.
        """
        self.baseurl = f"https://{host}:{port}/api/sonicos/"
        self.authinfo = (username, password)
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Accept-Encoding': 'application/json',
            'Charset': 'UTF-8'
        }
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        """
        Internal method to make HTTP requests and handle errors.
        """
        url = self.baseurl + endpoint
        try:
            response = requests.request(
                method,
                url,
                auth=self.authinfo,
                headers=self.headers,
                verify=self.verify_ssl,
                **kwargs
            )
            if response.status_code >= 400:
                raise SonicwallAPIError(f"HTTP {response.status_code}: {response.text}")
            if 'application/json' in response.headers.get('Content-Type', ''):
                return response.json()
            return response.text
        except requests.RequestException as err:
            raise SonicwallAPIError(f"Request failed: {err}")

    def authenticate(self) -> bool:
        """
        Authenticate with the SonicWall device.
        Returns True if successful, raises on failure.
        """
        endpoint = 'auth'
        result = self._request('POST', endpoint)
        # If no exception, authentication succeeded
        return True

    def config_mode(self) -> Any:
        """
        Enter configuration mode.
        """
        endpoint = "config-mode"
        return self._request('POST', endpoint)

    def commit_changes(self) -> Any:
        """
        Commit pending configuration changes.
        """
        endpoint = "config/pending"
        return self._request('POST', endpoint)

    def logout_user(self, username: str) -> Any:
        """
        Log out a user session by username.
        """
        endpoint = f"user/session/name/{username}"
        return self._request('DELETE', endpoint)

    def post_ipv4_address_object(
        self,
        address_name: str,
        obj_type: str,
        zone: str,
        host_ip: Optional[str] = None,
        range_begin: Optional[str] = None,
        range_end: Optional[str] = None,
        network_subnet: Optional[str] = None,
        network_mask: Optional[str] = None
    ) -> Any:
        """
        Create an IPv4 address object.
        """
        endpoint = 'address-objects/ipv4'
        config = None
        if obj_type == 'host':
            config = {
                "address_object": {
                    "ipv4": {
                        "name": address_name,
                        "host": {"ip": host_ip},
                        "zone": zone
                    }
                }
            }
        elif obj_type == 'range':
            config = {
                "address_object": {
                    "ipv4": {
                        "name": address_name,
                        "range": {"begin": range_begin, "end": range_end},
                        "zone": zone
                    }
                }
            }
        elif obj_type == 'network':
            config = {
                "address_object": {
                    "ipv4": {
                        "name": address_name,
                        "network": {"subnet": network_subnet, "mask": network_mask},
                        "zone": zone
                    }
                }
            }
        else:
            raise ValueError("Invalid object type. Must be 'host', 'range', or 'network'.")
        return self._request('POST', endpoint, json=config)

    def get_address_object_config(self) -> Any:
        """
        Get all IPv4 address objects.
        """
        endpoint = 'address-objects/ipv4'
        return self._request('GET', endpoint)

    def configure_ipv4_group(self, group_name: str, object_names: List[str], group_names: List[str]) -> Any:
        """
        Configure an IPv4 address group.
        """
        endpoint = 'address-groups/ipv4'
        object_names_list = []
        for item in object_names:
            object_names_list.append({"name": item})
        group_names_list = []
        for item in group_names:
            group_names_list.append({"name": item})
        config = {
            "address_groups": [
                {
                    "ipv4": {
                        "name": group_name,
                        "address_group": {
                            "ipv4": group_names_list
                        },
                        "address_object": {
                            "ipv4": object_names_list,
                        }
                    }
                }
            ]
        }
        if len(object_names) == 0:
            del config["address_groups"][0]["ipv4"]["address_object"]
        if len(group_names) == 0:
            del config["address_groups"][0]["ipv4"]["address_group"]
        return self._request('POST', endpoint, json=config)

    def get_groups_config(self) -> Any:
        """
        Get all IPv4 address groups.
        """
        endpoint = 'address-groups/ipv4'
        return self._request('GET', endpoint)

    def get_interface_config(self) -> Any:
        """
        Get interface configuration.
        """
        endpoint = 'interfaces/ipv4'
        return self._request('GET', endpoint)

    def configure_interface(
        self,
        interface_name: str,
        zone: str,
        ip_assignment_mode: str,
        dhcp_hostname: Optional[str] = None,
        enable_http: bool = False,
        enable_https: bool = False,
        enable_ping: bool = False,
        enable_snmp: bool = False,
        enable_ssh: bool = False,
        user_login_http: bool = False,
        user_login_https: bool = False,
        enable_https_redirect: bool = False,
        multicast: bool = True
    ) -> Any:
        """
        Configure an interface.
        """
        endpoint = 'interfaces/ipv4'
        config_static  = {
            "interfaces": [
                {
                    "ipv4": {
                        "name": interface_name,
                        "ip_assignment": {
                            "zone": zone,
                            "mode": {
                                "static": {
                                    "ip": "192.168.168.168",
                                    "netmask": "255.255.255.0",
                                    "gateway": "0.0.0.0"
                                }
                            }
                        },
                        "comment": "Configured via API",
                        "management": {
                            "https": enable_https,
                            "ping": enable_ping,
                            "snmp": enable_snmp,
                            "ssh": enable_ssh,
                            "fqdn_assignment": ""
                        },
                        "user_login": {
                            "http": user_login_http,
                            "https": user_login_https
                        },
                        "link_speed": {
                            "auto_negotiate": True
                        },
                        "mac": {
                            "default": True
                        },
                        "shutdown_port": False,
                        "auto_discovery": False,
                        "flow_reporting": True,
                        "multicast": multicast,
                        "cos_8021p": False,
                        "exclude_route": False,
                        "asymmetric_route": False,
                        "management_traffic_only": False,
                        "routed_mode": {},
                        "mtu": 1500
                    }
                }
            ]
        }
        config_dhcp = {
            "interfaces": [
                {
                    "ipv4": {
                        "name": interface_name,
                        "ip_assignment": {
                            "zone": zone,
                            "mode":{
                                "dhcp":{"hostname": dhcp_hostname}
                            }
                        },
                        "comment": "Configured via API",
                        "mtu": 1500,
                        "management": {
                            "http": enable_http,
                            "https": enable_https,
                            "ping": enable_ping,
                            "snmp": enable_snmp,
                            "ssh": enable_ssh
                        },
                        "user_login":{
                            "http":False,
                            "https":True
                        },
                        "https_redirect": enable_https_redirect
                    }
                }
            ]
        }
        config = None
        if ip_assignment_mode == "static":
            config = config_static  
        elif ip_assignment_mode == 'dhcp':  
            config = config_dhcp
        return self._request('PUT', endpoint, json=config)

    def get_configure_administration(self) -> Any:
        """
        Get administration configuration.
        """
        endpoint = 'administration/global'
        return self._request('GET', endpoint)

    def configure_administration(
        self,
        firewall_name: str = 'Default Name',
        http_port: int = 80,
        https_port: int = 443,
        idle_time: int = 20,
        enable_cloud_backup: bool = True
    ) -> Any:
        """
        Configure administration settings.
        """
        endpoint = 'administration/global'
        config = {
            "administration": {
                "firewall_name": firewall_name,
                "http_port": http_port,
                "https_port": https_port,
                "idle_logout_time": idle_time
            }
        }
        return self._request('PUT', endpoint, json=config)

    def configure_sslvpn_server(self, sslvpn_port: int) -> Any:
        """
        Configure SSL VPN server port.
        """
        endpoint = 'ssl-vpn/server'
        config = {
            "ssl_vpn":{
                "server":{
                    "port": sslvpn_port
                }
            }
        }
        return self._request('PUT', endpoint, json=config)

    def configure_dhcp_server(self, object_name: str, number: int, isarray: bool, value: str) -> Any:
        """
        Configure a DHCP server option.
        """
        endpoint = 'dhcp-server/ipv4'
        config = {
            "dhcp_server": {
                "ipv4": {
                    "option":{
                        "object":[
                            {
                                "name": object_name,
                                "number": number,
                                "array": isarray,
                                "value":[
                                    {
                                        "string":value
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
        return self._request('POST', endpoint, json=config)

    def get_dhcp_server_config(self) -> Any:
        """
        Get DHCP server configuration.
        """
        endpoint = 'dhcp-server/ipv4'
        return self._request('GET', endpoint)

    def configure_dhcp_server_base(self, enabled: bool, conflictdetection: bool, persistance: Dict[str, Any]) -> Any:
        """
        Configure DHCP server base settings.
        """
        endpoint = 'dhcp-server/ipv4'
        config = {
            "dhcp_server": {
                "ipv4": {
                    "enable":enabled,
                    "conflict_detection":True,
                    "persistence":persistance
                }
            }
        }
        return self._request('PUT', endpoint, json=config)

    def configure_zone(
        self,
        zone_name: str,
        security_type: str,
        interface_trust: bool = False,
        allow_from_equal: bool = True,
        allow_from_higher: bool = True,
        allow_to_lower: bool = True,
        deny_from_lower: bool = True,
        gateway_antivirus: bool = False,
        intrusion_prevention: bool = False,
        anti_spyware: bool = False,
        app_control: bool = False,
        dpi_ssl_client: bool = False,
        dpi_ssl_server: bool = False,
        create_group_vpn: bool = False,
        ssl_control: bool = False,
        sslvpn_access: bool = False
    ) -> Any:
        """
        Configure a security zone.
        """
        endpoint = 'zones'
        config = {
            "zones": [{
                "name": zone_name,
                "security_type": security_type,
                "interface_trust": interface_trust,
                "auto_generate_access_rules": {
                    "allow_from_to_equal": allow_from_equal,
                    "allow_from_higher": allow_from_higher,
                    "allow_to_lower": allow_to_lower,
                    "deny_from_lower": deny_from_lower
                },
                "gateway_anti_virus": gateway_antivirus,
                "intrusion_prevention": intrusion_prevention,
                "anti_spyware": anti_spyware,
                "app_control": app_control,
                "dpi_ssl_client": dpi_ssl_client,
                "dpi_ssl_server": dpi_ssl_server,
                "create_group_vpn": create_group_vpn,
                "ssl_control": ssl_control,
                "sslvpn_access":sslvpn_access
            }]
        }
        return self._request('POST', endpoint, json=config)

    def get_zone_config(self) -> Any:
        """
        Get all security zones.
        """
        endpoint = 'zones'
        return self._request('GET', endpoint)

    def configure_access_rule(
        self,
        rule_name: str,
        enabled: bool,
        logging: bool,
        fragments: bool,
        from_zone: str,
        to_zone: str,
        action: str,
        comment: Optional[str] = None,
        source_address: Optional[str] = None,
        source_address_value: Optional[str] = None,
        source_port: Optional[str] = None,
        source_port_value: Optional[str] = None,
        service: Optional[str] = None,
        service_value: Optional[str] = None,
        destination: Optional[str] = None,
        destination_value: Optional[str] = None,
        schedule: Optional[str] = None,
        schedule_value: Optional[str] = None,
        included_users: Optional[str] = None,
        Included_users_value: Optional[str] = None,
        excluded_users: Optional[str] = None,
        excluded_users_value: Optional[str] = None
    ) -> Any:
        """
        Configure an access rule.
        """
        endpoint = 'access-rules/ipv4'
        config = {
            "access_rules": [
                {
                "ipv4":{
                    "from": from_zone,
                    "to": to_zone,
                    "action": action,
                    "source":{"address":{source_address:source_address_value},"port":{source_port:source_port_value}},
                    "service": {service:service_value},
                    "destination": {"address":{destination:destination_value}},
                    "schedule": {schedule:schedule_value},
                    "users": {"included":{included_users:Included_users_value},"excluded":{excluded_users:excluded_users_value}},
                    "name": rule_name,
                    "comment": comment,
                    "enable": enabled,
                    "logging": logging,
                    "fragments": fragments
                }
            }]
        }
        return self._request('POST', endpoint, json=config)

    def get_access_rules_config(self) -> Any:
        """
        Get all access rules.
        """
        endpoint = 'access-rules/ipv4'
        return self._request('GET', endpoint)

    def configure_anti_spam(self, enabled: bool) -> Any:
        """
        Configure anti-spam settings.
        """
        endpoint = 'anti-spam/settings'
        config = {"anti_spam": {"enable": enabled}}
        return self._request('POST', endpoint, json=config)

    def get_anti_spam_config(self) -> Any:
        """
        Get anti-spam configuration.
        """
        endpoint = 'anti-spam/settings'
        return self._request('GET', endpoint)

    def configure_realtime_blacklisting(self, rbl_anable: bool, dns: str, domain: str, service_enable: bool, block_all: bool) -> Any:
        """
        Configure real-time blacklisting.
        """
        endpoint = 'anti-spam/settings'
        config = {
            "rbl": {
                "enable": rbl_anable,
                "dns": {dns},
                "service": [
                    {
                        "domain": domain,
                        "enable": service_enable,
                        "blocked_responses": {"block_all": block_all}
                    }
                ]
            }
        }
        return self._request('POST', endpoint, json=config)

    def get_realtime_blacklisting_config(self) -> Any:
        """
        Get real-time blacklisting configuration.
        """
        endpoint = 'anti-spam/settings'
        return self._request('GET', endpoint)

    def configure_ssl_control(self) -> Any:
        """
        Configure SSL control settings.
        """
        endpoint = 'ssl-control/'
        config = {
        "ssl_control": {
            "enable": True,
            "action": "block",
            "blacklist": True,
            "whitelist": True,
            "detect": {
            "ssl_v2": False,
            "ssl_v3": False,
            "weak_ciphers": False,
            "self_signed": True,
            "weak_digest_cert": False,
            "expired": False,
            "untrusted_ca": True,
            "tls_v1": False
            }
        }
        }
        return self._request('PUT', endpoint, json=config)

    def configure_time(self) -> Any:
        """
        Configure time settings.
        """
        endpoint = 'time/'
        config = {
            "time": {
                "use_ntp": True,
                "time_zone": "central-time",
                "daylight_savings": True
            }
        }
        return self._request('PUT', endpoint, json=config)

    def configure_firewall(self) -> Any:
        """
        Configure firewall settings.
        """
        endpoint = 'firewall/'
        config = {
            "firewall": {
                "stealth_mode": True,
                "randomize_id": True,
                "decrement": {"ttl": True},
                "icmp": {"redirect_on_lan": True},
                "rtsp_transformations": True,
                "drop": {"source_routed": True},
                "ipv6": {"icmp": {"time_exceeded": True}}
            }
            }
        return self._request('PUT', endpoint, json=config)

    def configure_security_services(self) -> Any:
        """
        Configure security services.
        """
        endpoint = 'security-services/'
        config = {
            "security_services": {
                "security": "maximum",
                "reduce_isdn_antivirus_traffic": False,
                "drop_packets_at_reload": False,
                "http_clientless_notification_timeout": 86400
            }
            }
        return self._request('PUT', endpoint, json=config)

    def configure_voip(self) -> Any:
        """
        Configure VoIP settings.
        """
        endpoint = 'voip'
        config = {
            "voip": {
                "consistent_nat": True,
                "sip": {},
                "h323": {}
            }
        }
        return self._request('PUT', endpoint, json=config)

    def configure_anti_spyware(self) -> Any:
        """
        Configure anti-spyware settings.
        """
        endpoint = 'security-services/'
        config = ""
        return self._request('PUT', endpoint, json=config)

    def configure_failover_lb(self) -> Any:
        """
        Configure failover load balancing.
        """
        endpoint = 'failover-lb/'
        config = ""
        return self._request('GET', endpoint)

    def get_device_info(self) -> Any:
        """
        Get device information.
        """
        endpoint = 'version/'
        r = self._request('GET', endpoint)
        if r.get('firmware_version'):
            device_info = r
            firmware_full = device_info.get('firmware_version', 'Unknown')
            firmware_cleaned = firmware_full.split()[-1] if firmware_full != 'Unknown' else 'Unknown'
            numeric_firmware = re.sub(r'[^0-9.]', '', firmware_cleaned)
            device_info['firmware_version'] = numeric_firmware
            return device_info
        else:
            return {"error": f"Failed to retrieve info, status code {r.get('status_code', 'Unknown')}"}

    def get_interface_configuration(self) -> Any:
        """
        Fetch interface configuration and extract relevant details.
        """
        endpoint = 'interfaces/configuration/'
        try:
            r = self._request('GET', endpoint)
            if r.get('interfaces'):
                interfaces_data = r
                extracted_interfaces = []
                for interface in interfaces_data.get("interfaces", []):
                    ipv4 = interface.get("ipv4", {})
                    extracted_interfaces.append({
                        "name": ipv4.get("name", "Unknown"),
                        "management_options": ipv4.get("management", {}),
                        "user_login_options": ipv4.get("user_login", {}),
                        "https_redirect": ipv4.get("https_redirect", False),
                        "multicast": ipv4.get("multicast", False),
                    })
                return {"interfaces": extracted_interfaces}
            else:
                return {"error": f"Failed to retrieve interface config, status code {r.get('status_code', 'Unknown')}"}
        except requests.exceptions.RequestException as err:
            return {"error": f"Request failed: {err}"}

    def configure_service_object(self, name: str, con_type: str, begin: int, end: int) -> Any:
        """
        Configure a service object.
        """
        endpoint = 'service-objects'
        config= {
                    "service_objects": 
                    [
                        {
                            "name": name,
                            con_type:{"begin":begin,"end":end}
                        }
                    ]
                } 
        return self._request('POST', endpoint, json=config)

    def get_service_object_config(self) -> Any:
        """
        Get all service objects.
        """
        endpoint = 'service-objects'
        return self._request('GET', endpoint)

    def configure_service_group(self, name: str, service_objects: List[str]) -> Any:
        """
        Configure a service group.
        """
        endpoint = 'service-groups'
        object_names_list = []
        for item in service_objects:
            object_names_list.append({"name": item})
        config = {
            "service_groups": [
                {
                    "name": name,
                    "service_object": object_names_list
                }
            ]
        }
        return self._request('POST', endpoint, json=config)

    def get_service_group_config(self) -> Any:
        """
        Get all service groups.
        """
        endpoint = 'service-groups'
        return self._request('GET', endpoint)













