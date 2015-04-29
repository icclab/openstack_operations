#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
 Copyright 2014 Zuercher Hochschule fuer Angewandte Wissenschaften
 All Rights Reserved.
    Licensed under the Apache License, Version 2.0 (the "License"); you may
    not use this file except in compliance with the License. You may obtain
    a copy of the License at
         http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.
"""

import nmap
from novaclient.v1_1 import Client
import json
from datetime import datetime

OS_AUTH_URL = ''
OS_USERNAME = ''
OS_PASSWORD = ''
OS_TENANT_ID = ''

IP_RANGE = ''

FILENAME = 'NMap-{0}-{1}.json'.format(datetime.now().month, datetime.now().day)
FILTERED_PORTS = [22, 80]


class NmapServers():
    def __init__(self):
        self.name = ''
        self.user = ''
        self.tenant = ''
        self.host = ''
        self.state = ''
        self.ports = []

    def nmap(self, nm, host, oh):
        self.host = host
        self.state = nm[host].state()
        protocol = nm[host].all_protocols()
        for proto in protocol:
            if proto == 'tcp':
                lport = nm[host][proto].keys()
                lport.sort()
                for port in lport:
                    self.ports.append({'port': port, 'state':  nm[host][proto][port]['state'],
                                       'name': nm[host][proto][port]['name'],
                                       'reason': nm[host][proto][port]['reason']})
        for port in self.ports:
            if port['port'] not in FILTERED_PORTS and port['state'] == 'open':
                nova = Client(**nova_credentials())
                servers = nova.servers.list(search_opts={'all_tenants': True})

                for server in servers:
                    for ips in getattr(server, 'networks').values():
                        if host in ips:
                            self.name = server.name
                            self.user = server.user_id
                            self.tenant = server.tenant_id
                            oh.append(self.__dict__)
                break


def nova_credentials():
    return dict(username=OS_USERNAME, api_key=OS_PASSWORD, project_id=OS_TENANT_ID,
                auth_url=OS_AUTH_URL)


def write_file(data):
    with open(FILENAME, 'w') as f:
        json.dump(data, f, sort_keys=True, indent=4, ensure_ascii=False)


def main():
    nm = nmap.PortScanner()
    nm.scan(IP_RANGE)
    open_hosts = list()
    for host in nm.all_hosts():
        nsv = NmapServers()
        nsv.nmap(nm, host, open_hosts)

    write_file(dict(VMs=open_hosts, number_vms=len(open_hosts)))

if __name__ == '__main__':
    main()
