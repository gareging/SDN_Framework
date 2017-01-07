Tables:

self.ip_mac_port: Collection of all interfaces connected to the OVS switch with dpid (key: IP address, fields (MAC, PORT))
Example: 
{99768326352716: {'10.10.4.7': ('02:e5:21:c2:bd:fb', 2)}}

self.configuration: table for the configuration: DEFAULT/IP_address;{PARAM*WEIGHT};TIMEOUT (key: IP address or DEFAULT). 
Example:
{'DEFAULT': ([('GE', '10'), ('CPU', '40'), ('DL', '50')], '2'), '10.5.5.1': ([('GE', 16), ('DL', 16), ('NX', 16), ('SS', 16), ('RR', 16), ('TT', 16)], '100'), '10.10.1.4': ([('GE', '30'), ('CPU', '70')], '60')}

self.number_of_servers: number of servers (key: SWITCH ID, field: number of servers)

self.servers: server info and values, key: SWITCH ID and SERVER ID [1 to ...]
Example:
{99768326352716: {0: '0', 1: ['10.10.4.7', [83.4688905899, 10.0, 10.0]]}}

self.serverLoad: current serverLoad (key - SWITCH ID)
{99768326352716: [0, 110, 23, 33]}

