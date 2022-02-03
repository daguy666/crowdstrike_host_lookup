#!/usr/bin/env python

import os
import sys 
import time
import json
import keyring
import urllib3
import datetime
import requests


class CrowdStrike_Info_Gatherer(object):

    def __init__(self, user_agent_id):
        self.user_inputted_agent_id = user_agent_id
        # Objects 
        self.cid = 'cs_client_id'
        self.sid = 'cs_secret_id'
        # Obtain creds from keychain
        self.cs_client_id = keyring.get_password(self.cid, self.cid)
        self.cs_secret_id = keyring.get_password(self.sid, self.sid)
        # URL details 
        self.base_cs_url = "https://api.crowdstrike.com"
        self.oauth_token = "/oauth/token" # not sure if needed yet.
        self.device_query_enpoint = "/indicators/queries/devies/v1"
        self.device_entities_endpoint = "/devices/entities/devices/v1"
        self.list_all_agent_id = "/devices/queries/devices/v1"
        # session
        self.session = requests.session()
        # Agent list
        self.all_agent_ids = []
        # Bearer token storage
        self.bearer_token = self.get_auth_token()

    def get_auth_token(self):
        """
        This code makes the initial api request to 
        obtain the bearer token. Make the intial api request
        to oauth/token to retrieve the bearer token.
        """
        url = "https://api.crowdstrike.com/oauth2/token"
        payload = 'client_secret=' + self.cs_secret_id + '&client_id=' + self.cs_client_id
        response = requests.request("POST", url, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data=payload)
        if response.ok:
            response_object = (response.json())
            token = response_object.get('access_token', '')
            if token:
                return token
        return

    def make_api_call(self):
        """
        Make second API call to obtain data.
        This is a hardcoded with an agent id, 
        this method is for testing out.
        """
        # Hardcode the aid for now, but next step is to obtain all of the aids for the org, and then loop a request for each one. 
        #print("Calling " + self.base_cs_url + self.device_entities_endpoint + '?ids=F<snip>234d ...')
        r = requests.get(self.base_cs_url + self.device_entities_endpoint +'?ids=' + self.user_inputted_agent_id, headers={'accept':'application/json', 'Authorization':'Bearer %s' % self.bearer_token})
        return r.json()
    
    def parse_and_display(self):
        """
        Create objects and return the to the end user.
        """
        # Call the make_api_call method
        crowdstrike_output = self.make_api_call()
        # Create objects to return to end user
        for i in crowdstrike_output['resources']:

            # Validate these so they dont error out.
            external_ip = i['external_ip']
            last_seen = i['last_seen']
            mac_address = i['mac_address']
            os_ver = i['os_version']
            #detection_suppression_status = i['detection_suppression_status']
            hostname = i['hostname']
            platform = i['platform_name']
            agent_version = i['agent_version']
            agent_local_time = i['agent_local_time']
            device_id = i['device_id']
            local_ip = i['local_ip']
            cs_version = i['agent_version']
            serial_number = i['serial_number']
        
        output_string = r"""
                             
            |------------------------------------------------| 
            |----------- CROWDSTRIKE HOST LOOKUP ------------|
            |------------------------------------------------|
                [+] Hostname: %s
                [+] Device Serial Number: %s
                [+] CS Agent ID: %s
                [+] Last Seen: %s
                [+] Agent Version: %s
                [+] Mac Address: %s
                [+] Public IP: %s
                [+] Local IP: %s
                [+] OS Version: %s
                [+] Platform: %s 
                [+] Agent Local Time: %s
                [+] Crowdstrike Version: %s
            |------------------------------------------------|
                """ %          (hostname,
                               serial_number,
                               device_id,
                               last_seen,
                               agent_version,
                               mac_address,
                               external_ip,
                               local_ip,
                               os_ver,
                               platform,
                               agent_local_time,
                               cs_version)
                               
        print(output_string)
    
    def main(self):
        """
        fire it up!
        """
        self.get_auth_token()
        self.parse_and_display()
 

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit('[!] Usage %s <agent_id>' % sys.argv[0])
    
    user_agent_id = sys.argv[1]
    # I am making the assumption that all agent ids are 32 characters in length
    if len(user_agent_id) != 32:
        print('[?] Check the format of the Agent ID.')
        sys.exit()
    else:
        csig = CrowdStrike_Info_Gatherer(user_agent_id)
        csig.main()

