import requests
import json
from collections import OrderedDict
import time
import urllib3
import re



ip="192.168.168.168"
port="443"

username="admin"
password="password"

HTTPstatusCodes = {
    "200":"OK",
    "400":"Bad Request",
    "401":"Not Authorized",
    "403":"Forbidden",
    "404":"Not Found",
    "405":"Method Not Allowed",
    "406":"Not Acceptable",
    "413":"Request Body Too Large",
    "414":"Request URL too long",
    "500":"Internal Server Error",
    "503":"No Resources"
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SonicAPIClass:
    def __init__(self,hostIP,port,username,password):
        self.baseurl = "https://{0}:{1}/api/sonicos/".format(hostIP,str(port))
        self.authinfo = (username,password)
        self.headers = OrderedDict([
            ('Accept','application/json'),
            ('Content-Type','application/json'),
            ('Accept-Encoding','application/json'),
            ('Charset','UTF-8')])

    def configmode(self):
        endpoint = "config-mode"
        url = self.baseurl + endpoint
        try:
            r = requests.post(url,auth=self.authinfo,headers=self.headers,verify=False)
            return r.json()
        except requests.exceptions.RequestException as err:
            raise SystemExit(err)

    def authenticate(self):
        endpoint = 'auth'
        url = self.baseurl + endpoint
        try:
            r = requests.post(url, auth=self.authinfo,headers=self.headers,verify=False)
            return r.status_code
        except requests.exceptions.RequestException as err:
            raise SystemExit(err)

    def commitChanges(self):
        endpoint = "config/pending"
        url = self.baseurl + endpoint
        r = requests.post(url,auth=self.authinfo,headers=self.headers,verify=False)
        return r.json()
    
    def logoutUSer(self,uName):
        endpoint="user/session/name/" + uName
        url = self.baseurl + endpoint
        r = requests.delete(url,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code
    
    def postIPv4AddressObjects(self,address_name,type,zone,host_ip=None,range_begin=None,range_end=None,network_subnet=None,network_mask=None):
        endpoint = 'address-objects/ipv4'
        url = self.baseurl + endpoint
        config = None

        if type == 'host':
            config = {
                "address_object":{
                    "ipv4": {
                                "name": address_name,
                                "host":{"ip":host_ip},
                                "zone": zone
                            }
                }
            }
        elif type == 'range':
            config = {
                "address_object": {
                    "ipv4": {
                                "name": address_name,
                                "range": {"begin":range_begin,"end": range_end},
                                "zone": zone
                            }
                }
            }
        elif type == 'network':
            config = {
                "address_object": {
                    "ipv4": {
                        "name": address_name,
                        "network":{"subnet":network_subnet,"mask":network_mask},
                        "zone": zone
                    }
                }
            }

        r = requests.post(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code
    
    def configureInterface(self,interface_name,zone,ip_assignment_mode,dhcp_hostname,enable_http,enable_https,enable_ping,enable_snmp,enable_ssh,user_login_http,user_login_https,enable_https_redirect=False,multicast=True):
        endpoint = 'interfaces/ipv4'
        url = self.baseurl + endpoint

        allowed_zones = ["wan","lan"]
        allowed_modes = ["dhcp","static"]

        if zone.lower() not in allowed_zones:
            raise ValueError(f"Invalid zone: {zone}. Allowed values are: {', '.join(allowed_zones)}")
        if ip_assignment_mode.lower() not in allowed_modes:
            raise ValueError(f"Invalid mode: {ip_assignment_mode}. Allowed values are: {', '.join(allowed_modes)}")
        
        config_static  = {
            "interfaces": [
                {
                    "ipv4": {
                        "name": interface_name

                        ,"ip_assignment": {
                            "zone": zone

                            ,"mode": {
                                "static": {
                                    "ip": "192.168.168.168"
                                    ,"netmask": "255.255.255.0"
                                    ,"gateway": "0.0.0.0"
                                }
                            }
                        }

                        ,"comment": "ESTING"

                        ,"management": {
                            "https": enable_https
                            ,"ping": enable_ping
                            ,"snmp": enable_snmp
                            ,"ssh": enable_ssh
                            ,"fqdn_assignment": ""
                        }

                        ,"user_login": {
                            "http": user_login_http
                            ,"https": user_login_https
                        }

                        

                        ,"link_speed": {
                            "auto_negotiate": True
                        }

                        ,"mac": {
                            "default": True
                        }

                        ,"shutdown_port": False
                        ,"auto_discovery": False
                        ,"flow_reporting": True
                        ,"multicast": multicast
                        ,"cos_8021p": False
                        ,"exclude_route": False
                        ,"asymmetric_route": False
                        ,"management_traffic_only": False

                        ,"routed_mode": {
                        }

                        ,"mtu": 1500
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

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        print(r.text)
        return r.status_code
    
    def configure_administration(self,firewall_name,http_port,https_port,idle_time,enable_cloud_backup):
        endpoint = 'administration/global'
        url = self.baseurl + endpoint
        config = {
            "administration": {
                "firewall_name": firewall_name,
                "http_port": http_port,
                "https_port": https_port,
                "idle_logout_time": idle_time,
                "cloud_backup_enable":enable_cloud_backup
            }
        }

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code
    
    def configure_sslvpn_server(self,sslvpn_port):
        endpoint = 'ssl-vpn/server'
        url = self.baseurl + endpoint

        config = {
            "ssl_vpn":{
                "server":{
                    "port": sslvpn_port
                }
            }
        }
        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code
    
    def configure_dhcp_server(self,object_name,number,isarray,value):
        endpoint = 'dhcp-server/ipv4'
        url = self.baseurl + endpoint

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

        r = requests.post(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        #Add a check to see if it already Exists this will fail if the item is there
        return r.status_code
    
    def configure_dhcp_server_base(self,enabled,conflictdetection,persistance):
        endpoint = 'dhcp-server/ipv4'
        url = self.baseurl + endpoint

        config = {
            "dhcp_server": {
                "ipv4": {
                    "enable":enabled,
                    "conflict_detection":True,
                    "persistence":{}
                }
            }
        }

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        
        return r.status_code
    
    def configure_zone(self,zone_name,security_type,interface_trust=False,allow_from_equal=True,allow_from_higher=True,allow_to_lower=True,deny_from_lower=True,gateway_antivirus=False,intrusion_prevention=False,anti_spyware=False,app_control=False,dpi_ssl_client=False,dpi_ssl_server=False,create_group_vpn=False,ssl_control=False,ssl_vpn_access=False):
        endpoint = 'zones'
        url = self.baseurl + endpoint

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
                "sslvpn_access":ssl_vpn_access
            }]
        }
        r = requests.post(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code
    
    def configure_access_rule(self,rule_name,enabled,logging,fragments,comment,from_zone,to_zone,action,source_address=None,source_address_value=None,source_port=None,source_port_value=None,service=None,service_value=None,destination=None,destination_value=None,schedule=None,schedule_value=None,included_users=None,Included_users_value=None,excluded_users=None,excluded_users_value=None):
        endpoint = 'access-rules/ipv4'
        url = self.baseurl + endpoint

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

        r = requests.post(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        
        return r.status_code
    
    def configure_anti_spam(self,enabled):
        endpoint = 'anti-spam/settings'
        url = self.baseurl + endpoint

        config = {"anti_spam": {"enable": enabled}}

        r = requests.post(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code
    
    def configure_realtime_blacklisting(self,rbl_anable,dns,domain,service_enable,block_all):
        endpoint = 'anti-spam/settings'
        url = self.baseurl + endpoint
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

        r = requests.post(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        
        return r.status_code
    
    def configure_ssl_control(self):
        endpoint = 'ssl-control/'
        url = self.baseurl + endpoint
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

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        
        return r.status_code

    def configure_time(self):
        endpoint = 'time/'
        url = self.baseurl + endpoint

        config = {
            "time": {
                "use_ntp": True,
                "time_zone": "central-time",
                "daylight_savings": True
            }
        }

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        
        return r.status_code

    def configure_firewall(self):
        endpoint = 'firewall/'
        url = self.baseurl + endpoint

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

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code

    def configure_security_services(self):
        endpoint = 'security-services/'
        url = self.baseurl + endpoint

        config = {
            "security_services": {
                "security": "maximum",
                "reduce_isdn_antivirus_traffic": False,
                "drop_packets_at_reload": False,
                "http_clientless_notification_timeout": 86400
            }
            }

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code

    def configure_voip(self):
        endpoint = 'voip'
        url = self.baseurl + endpoint

        config = {
            "voip": {
                "consistent_nat": True

                ,"sip": {
                }

                ,"h323": {
                }
            }
        }

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code

    def configure_anti_spyware(self):
        endpoint = 'security-services/'
        url = self.baseurl + endpoint

        config = ""

        r = requests.put(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code

    def configure_failover_lb(self):
        endpoint = 'failover-lb/'
        url = self.baseurl + endpoint

        config = ""

        r = requests.get(url,json=config,auth=self.authinfo,headers=self.headers,verify=False)
        return r.status_code

    def get_device_info(self):
        endpoint = 'version/'
        url = self.baseurl + endpoint

        r = requests.get(url, auth=self.authinfo, headers=self.headers, verify=False)
        
        if r.status_code == 200:
            device_info = r.json()
            firmware_full = device_info.get('firmware_version', 'Unknown')

            # Extract only the last part of the firmware string
            firmware_cleaned = firmware_full.split()[-1] if firmware_full != 'Unknown' else 'Unknown'

            # Remove non-numeric characters while preserving dots (e.g., '6.5.4.8-89n' → '6.5.4.8')
            numeric_firmware = re.sub(r'[^0-9.]', '', firmware_cleaned)

            # Update the session with the cleaned version
            device_info['firmware_version'] = numeric_firmware
            return device_info
        else:
            return {"error": f"Failed to retrieve info, status code {r.status_code}"}    

    def get_interface_configuration(self):
        """Fetch interface configuration and extract relevant details."""
        endpoint = 'interfaces/configuration/'
        url = self.baseurl + endpoint

        try:
            r = requests.get(url, auth=self.authinfo, headers=self.headers, verify=False)

            if r.status_code == 200:
                interfaces_data = r.json()
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
                return {"error": f"Failed to retrieve interface config, status code {r.status_code}"}
        
        except requests.exceptions.RequestException as err:
            return {"error": f"Request failed: {err}"}



def authentication(firewall):
    authtry = 3

    while authtry > 0:
        authStatus = firewall.authenticate()
        if authStatus != 200:
            print("API authorization failed. Trying again in 5 secs!")
            authtry -= 1
            time.sleep(5)
        else:
            authtry = 0
    
    print("API authorization: ", end="")
    print("Status " + str(authStatus) + " " + HTTPstatusCodes[str(authStatus)])
    if authStatus != 200:
        print("Exiting Program.")
        exit()
    else:
        return("Status " + str(authStatus) + " " + HTTPstatusCodes[str(authStatus)])

def logout(firewall):
    print("\nLogging out from the firewall: ",end="")
    logoutStatus = firewall.logoutUser(username)
    print("Status " + str(logoutStatus) + " " + HTTPstatusCodes[str(logoutStatus)])

def commitChanges(firewall):
    print("Commit changes: ",end="")
    commitStatusJSON = firewall.commitChanges()
    status = commitStatusJSON['status']['success']
    message = commitStatusJSON['status']['info'][0]['message']
    commitStatus = str(status) + ", " + str(message)
    print(commitStatus + "\n")
    if status == False:
        print("Exiting program.")
        exit()

def startconfig(firewall):
    print("Starting Config Mode")
    configStatus = firewall.configmode()
    print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])


















#firewall = SonicAPIClass(ip,port,username,password)
#authentication(firewall)

#firewall.get_device_info()

'''
##################################### SCRIPT TESTING #################################

configStatus = firewall.configureInterface("X0","LAN","static","AT&T",True,True,True,True,True,True,True,True,True)
print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])

configStatus = firewall.configureInterface("X1","WAN","dhcp","AT&T",True,True,True,True,True,True,True,True,True)
print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])

commitChanges(firewall)


"""
ITEMS COMPLETE:

ITEMS THAT NEED WORK:
"""
'''