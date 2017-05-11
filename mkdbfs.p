uses
   display, math, classes, strings, environment, datetime, databases,
   hashes, compression;

var
   BlacklistDBF:THalcyonDataset; // manual, or RBL failed
   WhitelistDBF:THalcyonDataset; // manual or successful SSH
   RBLCache:THalcyonDataset;     // Clean Database - so we do not have to pay spamhaus for volume!
   DomainsDBF:THalcyonDataset;   // Hosted domains and alias domains - no users!
   RelayCache:THalcyonDataset;   // Everytime someone tries to relay off us, their IP is added here - 7 times - Blacklist!
   SiteDBF:THalcyonDataset;      // Complete Configuration per Domain
   UsersDBF:THalcyonDataset;     // Complete Users Database per Domain
   IndexFiles:TStringList;
   Schema:TStringList;
   Field:TField;
   ScriptRoot:String;            // CodeRunner runs from another directory - so I store the path to this apps source and data

Procedure CreateDatabases;
begin
   WhitelistDBF.Init(Nil);
   WhitelistDBF.setFilename(ScriptRoot+'data/whitelist.dbf');
   If not FileExists(ScriptRoot+'data/whitelist.dbf') then begin
      Schema.Init;
      Schema.Add('IPADDR,C,15,0');
      Schema.Add('SOURCE,C,20,0'); // Program that added to this DB
      WhitelistDBF.createDBF(ScriptRoot+'data/whitelist.dbf','',FoxPro,Schema);
      Schema.Free;
      WhitelistDBF.Open;
      WhitelistDBF.IndexOn(ScriptRoot+'data/whitelist.cdx','PK','IPADDR','.NOT.DELETED()',Unique,Ascending);
      WhitelistDBF.Close;
   End;
   WhitelistDBF.Free;

   BlacklistDBF.Init(Nil);
   BlacklistDBF.setFilename(ScriptRoot+'data/blacklist.dbf');
   If not FileExists(ScriptRoot+'data/blacklist.dbf') then begin
      Schema.Init;
      Schema.Add('IPADDR,C,15,0');
      Schema.Add('ADDEDON,N,20,0');
      BlacklistDBF.createDBF(ScriptRoot+'data/blacklist.dbf','',FoxPro,Schema);
      Schema.Free;
      BlacklistDBF.Open;
      BlacklistDBF.IndexOn(ScriptRoot+'data/blacklist.cdx','PK','IPADDR','.NOT.DELETED()',Unique,Ascending);
      BlacklistDBF.Close;
   End;
   BlacklistDBF.Free;

   RBLCache.Init(Nil);
   RBLCache.setFilename(ScriptRoot+'data/rblcache.dbf');
   If not FileExists(ScriptRoot+'data/rblcache.dbf') then begin
      Schema.Init;
      Schema.Add('IPADDR,C,15,0');
      Schema.Add('EXPIRES,N,20,0');
      RBLCache.createDBF(ScriptRoot+'data/rblcache.dbf','',FoxPro,Schema);
      Schema.Free;
      RBLCache.Open;
      RBLCache.IndexOn(ScriptRoot+'data/rblcache.cdx','PK','IPADDR','.NOT.DELETED()',Unique,Ascending);
      RBLCache.Close;
   End;
   RBLCache.Free;

   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   If not FileExists(ScriptRoot+'data/domains.dbf') then begin
      Schema.Init;
      Schema.Add('DOMAIN,C,65,0');
      DomainsDBF.createDBF(ScriptRoot+'data/domains.dbf','',FoxPro,Schema);
      Schema.Free;
      DomainsDBF.Open;
      DomainsDBF.IndexOn(ScriptRoot+'data/domains.cdx','PK','DOMAIN','.NOT.DELETED()',Unique,Ascending);
      DomainsDBF.Close;
   End;
   DomainsDBF.Free;

   RelayCache.Init(Nil);
   RelayCache.setFilename(ScriptRoot+'data/relaycache.dbf');
   If not FileExists(ScriptRoot+'data/relaycache.dbf') then begin
      Schema.Init;
      Schema.Add('IPADDR,C,15,0');
      Schema.Add('TRIES,N,6,0');
      RelayCache.createDBF(ScriptRoot+'data/relaycache.dbf','',FoxPro,Schema);
      Schema.Free;
      RelayCache.Open;
      RelayCache.IndexOn(ScriptRoot+'data/relaycache.cdx','PK','IPADDR','.NOT.DELETED()',Unique,Ascending);
      RelayCache.Close;
   End;
   RelayCache.Free;

   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   While not DomainsDBF.getEOF do begin
      Field:=DomainsDBF.getFieldByName('DOMAIN');
      CreateDirEx(ScriptRoot+'data/'+Field.getAsString+'/');
      CreateDirEx(ScriptRoot+'inbox/'+Field.getAsString+'/');
      If not FileExists(ScriptRoot+'data/'+Field.getAsString+'/system.dbf') then begin
         SiteDBF.Init(Nil);
         SiteDBF.setFilename(ScriptRoot+'data/'+Field.getAsString+'/system.dbf');
         Schema.Init;
         Schema.Add('ACTIVE,L,1,0');    // Account Enabled
         Schema.Add('COMPANY,C,55,0');  // Company
         Schema.Add('INIT,C,55,0');     // Company Unit/Department - part of SSL
         Schema.Add('STREET,C,55,0');   // Street
         Schema.Add('CITY,C,35,0');     // City - part of SSL
         Schema.Add('STATE,C,15,0');    // State - part of SSL
         Schema.Add('ZIP,C,15,0');      // Zip
         Schema.Add('COUNTRY,C,55,0');  // Country - part of SSL
         Schema.Add('BCCIN,L,1,0');     // Monitor incoming email via BCC
         Schema.Add('BCCOUT,L,1,0');    // Monitor outgoing email via BCC
         Schema.Add('BCCINTO,C,80,0');  // BCC incoming to email address
         Schema.Add('BCCOUTTO,C,80,0'); // BCC outgoing to email address
         Schema.Add('CATCHALL,L,1,0');  // Enable Catch-All for Unknown Email
         Schema.Add('CATCHTO,C,80,0');  // Catch-All email address
         Schema.Add('ALIASOK,L,1,0');   // Enable ALIAS domains
         Schema.Add('ALIASES,C,240,0'); // comma-delimited list of domains to accept under this domain (must be in domains.dbf)
         Schema.Add('FLOWIN,L,1,0');    // Enable inbound throttling
         Schema.Add('FLOWOUT,L,1,0');   // Enable outgoing throttling
         Schema.Add('INPERDAY,L,1,0');  // Throttle inbound by Per Day
         Schema.Add('INPERWK,L,1,0');   // Throttle inbound by Per Week
         Schema.Add('INPERMIN,L,1,0');  // Throttle inbound by Per Minute
         Schema.Add('OUTPERDAY,L,1,0'); // Throttle outgoing by Per Day
         Schema.Add('OUTPERWK,L,1,0');  // Throttle outgoing by Per Week
         Schema.Add('OUTPERMIN,L,1,0'); // Throttle outgoing by Per Minute
         Schema.Add('INMAXMSG,N,20,0'); // Throttle inbound maximum PER (above)
         Schema.Add('OUTMAXMSG,N,20,0');// Throttle outgoing maximum PER (above)
         Schema.Add('MAXUSERS,N,20,0'); // Max mail users
         Schema.Add('MAXLISTS,N,20,0'); // Max mail lists
         Schema.Add('MAXALIAS,N,20,0'); // Max domain aliases
         Schema.Add('MINPWRLEN,N,20,0');// Minimum Password Length
         Schema.Add('MAXPWDLEN,N,20,0');// Maximum Password Length
         SiteDBF.createDBF(ScriptRoot+'data/'+Field.getAsString+'/system.dbf','',FoxPro,Schema);
         Schema.Free;
         SiteDBF.Close;
         SiteDBF.Free;
      end;
      If not FileExists(ScriptRoot+'data/'+Field.getAsString+'/users.dbf') then begin
         UsersDBF.Init(Nil);
         UsersDBF.setFilename(ScriptRoot+'data/'+Field.getAsString+'/users.dbf');
         Schema.Init;
         Schema.Add('EMAIL,C,80,0');    // Email Address
         Schema.Add('FNAME,C,35,0');    // First Name
         Schema.Add('LNAME,C,35,0');    // Last Name
         Schema.Add('PWDHASH,C,40,0');  // SHA-1 Hash of Password
         Schema.Add('ACTIVE,L,1,0');    // Account Enabled
         Schema.Add('DOMAIN,L,1,0');    // Domain Admin
         Schema.Add('GLOBAL,L,1,0');    // Global Admin
         Schema.Add('QUOTA,N,20,0');    // 0=Unlimited, MB of Disk Space Usage
         Schema.Add('EMPLOYID,C,35,0'); // Employee ID
         Schema.Add('DEPART,C,35,0');   // Department
         Schema.Add('TITLE,C,35,0');    // Job Title
         Schema.Add('MOBILE,C,20,0');   // Cell Phone #
         UsersDBF.createDBF(ScriptRoot+'data/'+Field.getAsString+'/users.dbf','',FoxPro,Schema);
         UsersDBF.Open;
         UsersDBF.IndexOn(ScriptRoot+'data/'+Field.getAsString+'/users.cdx','PK','EMAIL','.NOT.DELETED()',Unique,Ascending);
         UsersDBF.Close;
         Schema.Free;
         If (Field.getAsString='fido.pwnz.org') then begin
            IndexFiles:=UsersDBF.getIndexFiles;
            IndexFiles.Add(ScriptRoot+'data/'+Field.getAsString+'/users.cdx');
            UsersDBF.Open;
            UsersDBF.setIndexTag('PK');
            UsersDBF.Append;
            Field:=UsersDBF.getFieldByName('EMAIL');
            Field.setAsString('admin@fido.pwnz.org');
            Field:=UsersDBF.getFieldByName('PWDHASH');
            Field.setAsString(SHA1('password'));
            UsersDBF.Post;
         End;
         UsersDBF.Free;
      end;
      DomainsDBF.Next;
   End;
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

Begin
   ScriptRoot:=ExtractFilePath(ExecFilename);
   CreateDirEx(ScriptRoot+'data');
   CreateDirEx(ScriptRoot+'logs');
   CreateDirEx(ScriptRoot+'outbound');
   CreateDirEx(ScriptRoot+'inbox');
   CreateDatabases;
End.
