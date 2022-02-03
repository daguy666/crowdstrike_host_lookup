## `crowdstrike_host_lookup`
This is a Crowdstrike API client to return some system information about an endpoint using the Crowdstrike Agent ID.


This is a tool build to connect to the Crowdstrike API. This script will take a command line argument of a Crowdstrike agent ID. 

```
> python cs_hostlookup.py aaaaabbbbbcccccdddddeeeeefffffhh


            |------------------------------------------------|
            |----------- CROWDSTRIKE HOST LOOKUP ------------|
            |------------------------------------------------|
                [+] Hostname: Barts-MacBook-Pro.local
                [+] Device Serial Number: 123456789098
                [+] CS Agent ID: aaaaabbbbbcccccdddddeeeeefffffhh
                [+] Last Seen: 2020-10-29T19:52:41Z
                [+] Mac Address: ff-ff-ff-ff-ff-ff
                [+] Public IP: 1.1.1.1
                [+] Local IP: 192.168.1.2
                [+] OS Version: Catalina (10.15)
                [+] Platform: Mac
                [+] Agent Local Time: 2020-10-22T13:13:50.779Z
                [+] Crowdstrike Version: 12.34.56789.0
            |------------------------------------------------|
```


### installation:
`pip3 install -r requirements.txt`

Specifically just the keyring library to interact with keychain. 

<br>

---


<br>


```
>>> import cs_hostlookup
>>> help(cs_hostlookup)


Help on module cs_hostlookup:

NAME
    cs_hostlookup

FILE
    /Users/jpistone/git/crowdstrike_host_lookup/cs_hostlookup.py

CLASSES
    __builtin__.object
        CrowdStrike_Info_Gatherer

    class CrowdStrike_Info_Gatherer(__builtin__.object)
     |  Methods defined here:
     |
     |  __init__(self, user_agent_id)
     |
     |  get_auth_token(self)
     |      This code makes the initial api request to
     |      obtain the bearer token. Make the intial api request
     |      to oauth/token to retrieve the bearer token.
     |
     |  main(self)
     |      fire it up!
     |
     |  make_api_call(self)
     |      Make second API call to obtain data.
     |      This is a hardcoded with an agent id,
     |      this method is for testing out.
     |
     |  parse_and_display(self)
     |      Create objects and return the to the end user.