# TACACS+

Well, I was bored and RADIUS was playing up when trying to authenticate LDAP users with SSHA passwords, so I thought I'd write a TACACS+ server. Someone else has probably made a better one but I do enjoy writing servers for these weird protocols.

It's not finished yet and only tested with Cisco gear, but can do the following so far:

Authentication:
* Authenticate users in a config file

Authorisation
* Control what privilege level a user can enable to / auto-enable when logging in

Accounting
* Log command accounting info to stdout

* Push command accounting info to a redis pub/sub channel


In the `misc` folder theres a super hacky websocket webserver which displays a table and listens to a Redis pub/sub channel. 
Then if a device with TACACS+ command accounting is enabled + the TACACS+ server is publishing to Redis then it'll display commands in realtime.

TODO:
* Log command accounting info to file - in progress
* User authentication with LDAP - in progress
* Push command accounting info to dynamo - in progress
* Push command accounting info to kinesis - in progress
