# Email
Email Server - which runs our email service. I am still perecting some of the ESMTP rules. I am running all of this on the free CodeRunner2 engine (e.g. no SSL/TLS)... so I am working on hardening everything. I normally do not comment code, but, the scripts have a few comments to help you see where things are.

* TO DO:
 * SMTP Sender
 * IMAP4 Server
 * I have bayesian code, just need to learn it and merge it in.
 * Also looking at AMAVISD (Spam Assassin, Clam A/V) support.

My coderunner2.conf file:
```
[Listeners]
Servers=4

[Listener1]
Port=25
Blocking=Yes
Nagle=No
KeepAlive=Yes
ipaddr=0.0.0.0
OnConnect=/EMAIL/smtpserver.p

[Listener2]
Port=587
Blocking=Yes
Nagle=No
KeepAlive=Yes
ipaddr=0.0.0.0
OnConnect=/EMAIL/smtpserver.p

[Listener3]
Port=2525
Blocking=Yes
Nagle=No
KeepAlive=Yes
ipaddr=0.0.0.0
OnConnect=/EMAIL/smtpserver.p

[Listener4]
Port=110
Blocking=Yes
Nagle=No
KeepAlive=Yes
ipaddr=0.0.0.0
OnConnect=/EMAIL/popserver.p
```

## Setup/Configuration

* mkdbfs.p
This utility generates folders for the system, folders for new users, and all databases.

* domains.p
This utility updates the domains/users databases for new domains and new users.
