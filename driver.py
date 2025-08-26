import SonicwallAPI as sos
import json

ip="192.168.120.1"
port="444"

username="admin"
password="Password!"

firewall = sos.SonicAPIClass(ip,port,username,password)
sos.authentication(firewall)
#startconfig(firewall)

firewall.get_device_info()





################### GETTER TESTING ######################

sos.check_config_against_base(firewall)

sos.commitChanges(firewall)



##################################### SCRIPT TESTING #################################


'''configStatus = firewall.configureInterface(
    interface_name="X0",
    zone="LAN",
    ip_assignment_mode="static",
    dhcp_hostname="LAN",    
    enable_http=False,
    enable_https=True,
    enable_ping=True,
    enable_snmp=False,
    enable_ssh=True,
    user_login_http=False,
    user_login_https=True,
    enable_https_redirect=False,
    multicast=True)'''
#print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])

'''configStatus = firewall.configureInterface(
    interface_name="X1",
    zone="WAN",
    ip_assignment_mode="dhcp",
    dhcp_hostname="AT&T",
    enable_http=False,
    enable_https=True,
    enable_ping=True,
    enable_snmp=False,
    enable_ssh=True,
    user_login_http=False,
    user_login_https=True,
    enable_https_redirect=False,
    multicast=True)'''
#print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])

#Enable Anti-Spyware here

#Enable App-Control Here

#Enable Gateway-Antivirus Here

#Enable Intrusion Prevention Here
#print(firewall.configure_administration())



'''firewall.configure_administration(
    firewall_name="API Configured Firewall",
    http_port=80,
    https_port=4444,
    idle_time=10,
    enable_cloud_backup=True
    )'''
#print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])


#firewall.configure_sslvpn_server(sslvpn_port=443)
#print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])
#commitChanges(firewall)


'''configStatus = firewall.configure_administration(
    firewall_name="API Configured Firewall",
    http_port=80,
    https_port=4433,
    idle_time=10,
    enable_cloud_backup=True
    )'''
#print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])
#commitChanges(firewall)


#configStatus = firewall.configure_dhcp_server(object_name="VoIP Option",number=132,isarray=False,value="200")
#print("Status " + str(configStatus) + " " + HTTPstatusCodes[str(configStatus)])

#commitChanges(firewall)

'''
"""
ITEMS COMPLETE:

ITEMS THAT NEED WORK:
"""
'''