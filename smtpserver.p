Program SMTPServer.v1170404;

/////////////////////////////////////////////////////////////////////////////
// Script Name: smtpserver.p
//   Author(s): G.E. Ozz Nixon Jr.
//   Copyright: (c) 2017 by MP Solutions, LLC.
/////////////////////////////////////////////////////////////////////////////
// STILL IN DEVELOPMENT!
// ==========================================================================
// Defenses:
// 1. Three attempts or more to relay off our software - access is disabled.
// 2. RBL Fail, access is disabled for 72 hours.
// 3. Known users must authenticate before they can send me email.
// 4. domains.p manages "known domains" when checking if relay or auth needed.
/////////////////////////////////////////////////////////////////////////////
// on Centos make sure nslookup is installed if not:
// yum install bind-utils
// ==========================================================================
// TODO:
// 1. Support an array of RcptTo
// 2. DBF the outbound folder, with the array of who I am sending to and from
// 3. DBF the /Inbox/ folders, with what has been added since last login
// 4. Implement DKIM Signature, and update the domain DNS to match!
// ==========================================================================
/////////////////////////////////////////////////////////////////////////////

uses
   display, math, classes, strings, environment, datetime, databases,
   hashes, compression;

type
   opStates=(osReady,osHello,osAUTHPlain,osAUTHLogin,osToFrom,osData,osBye,osIgnore);

const
   cacheTTL=60*60*72; // 72hours
   defaultdomain='ip-132-148-27-199.ip.secureserver.net'; // REVERSE PTR
//   validemailcharacters="!$&*-=^`|~#%?+/_{}"; // +A..Z,0..9 before the @ sign!
   Numbering='1234567890QWERTYUIOPASDFGHJKLZXCVBNM';
   Pass7=78364164096;
   Pass6=2176782336;
   Pass5=60466176;
   Pass4=1679616;
   Pass3=46656;
   Pass2=1296;
   Pass1=36;
{$IFDEF WINDOWS}
   OSValue=1;
{$ENDIF}
{$IFDEF LINUX}
   OSValue=2;
{$ENDIF}
{$IFDEF MAC}
   OSValue=4;
{$ENDIF}

var
   BlacklistDBF:THalcyonDataset; // manual, or RBL failed
   RBLCache:THalcyonDataset;     // Clean Database - so we do not have to pay spamhaus for volume!
   DomainsDBF:THalcyonDataset;   // Hosted domains and alias domains - no users!
   RelayCache:THalcyonDataset;   // Everytime someone tries to relay off us, their IP is added here - 7 times - Blacklist!
   SiteDBF:THalcyonDataset;      // Complete Configuration per Domain
   UsersDBF:THalcyonDataset;     // Complete Users Database per Domain
   IndexFiles:TStringList;
   Schema:TStringList;
   ScriptRoot:String;            // CodeRunner runs from another directory - so I store the path to this apps source and data
   HelloStr:String;
   Username:String;
   Password:String;
   Authenticated:Boolean;
   MailFrom:String;
   MailFromDomain:String;
   MailFromKnown:Boolean;
   RcptTo:String;
   RcptToDomain:String;
   RcptToKnown:Boolean;
   CollectingHeader:Boolean;
   DataHeader:String;
   DataBody:String;

{$I /BBS/includes/logging.i}

function lookupMX(domain:string):string;
var
   StrList:TStringList;
   Loop:Longint;
   Ws:String;

begin
   ExecuteRun('/usr/bin/nslookup',['-query=MX',domain],Result);
   StrList.Init;
   StrList.setText(Result);
   Result:='';
   Loop:=0;
   While Loop<StrList.getCount-1 do
      If pos('exchanger',StrList.getStrings(Loop))>0 then Begin
         Ws:=StrList.getStrings(Loop);
         Fetch(Ws);
         Fetch(Ws);
         Fetch(Ws);
         Fetch(Ws);
         Result+=Copy(Ws,1,Length(Ws)-1)+#13#10;
         Inc(Loop);
      End
      Else StrList.Delete(Loop);
   StrList.setText(Result);
   Loop:=0;
   While Loop<StrList.getCount-1 do
      If StrList.getStrings(Loop)==StrList.getStrings(Loop+1) then
         StrList.Delete(Loop+1)
      Else Inc(Loop);
   Result:=StrList.getText;
   If Result<>'' then Result:=Copy(Result, 1, Length(Result)-1);
   StrList.Free;
end;

Function ReverseAddress(IP:String):String;
Begin
   Result:=Fetch(IP,'.');
   Result:=Fetch(IP,'.')+'.'+Result;
   Result:=Fetch(IP,'.')+'.'+Result;
   Result:=IP+'.'+Result;
End;

function QueryZen(IP:String):Boolean;
Var
   S:String;
   Field:TField;
   Found:Boolean;

Begin
   Found:=False;
   RBLCache.Init(Nil);
   RBLCache.setFilename(ScriptRoot+'data/rblcache.dbf');
   IndexFiles:=RBLCache.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/rblcache.cdx');
   RBLCache.Open;
   RBLCache.setIndexTag('PK');
   if RBLCache.Find(IP,True,False) then begin
      Field:=RBLCache.getFieldByName('EXPIRES');
      If Field.getAsInteger>Timestamp then begin
         Result:=True;
         RBLCache.Close;
         RBLCache.Free;
         Exit;
      End;
      Found:=True;
   End;
   Log('zen.spamhaus.org query for "'+IP+'"');
   Result:=False;
   ExecuteRun('/usr/bin/nslookup',['-query=TXT', ReverseAddress(IP)+'.zen.spamhaus.org'],S);
   If Pos('NXDOMAIN',S)>0 then begin
      Result:=True;
      If Found then Begin
         RBLCache.Edit;
         Field:=RBLCache.getFieldByName('EXPIRES');
         Field.setAsInteger(Timestamp+cacheTTL);
         RBLCache.Post;
      End
      Else Begin
         RBLCache.Append;
         Field:=RBLCache.getFieldByName('EXPIRES');
         Field.setAsInteger(Timestamp+cacheTTL);
         Field:=RBLCache.getFieldByName('IPADDR');
         Field.setAsString(IP);
         RBLCache.Post;
      End;
   end
   else Begin
      Log('RBL failed "'+IP+'"');
      Fetch(S,'text');
      Log(Copy(S,1,Pos(#10,S)-1));
   End;
   RBLCache.Close;
   RBLCache.Free;
End;

function RBLPassed:Boolean;
var
   StrList:TStringList;
   Loop:Longint;
   LastIP:String;
   OK:Boolean;

begin
   StrList.Init;
   StrList.SetText(lookupMX(MailFromDomain));
   If StrList.getCount<1 then Begin
      Log('MX lookup failed for "'+MailFromDomain+'"');
      Result:=False;
      StrList.Free;
      Exit;
   End;
   For Loop:=0 to StrList.getCount-1 do
      StrList.setStrings(Loop,Session.GetIPAddressByHost(StrList.getStrings(Loop),1));
   LastIP:='';
   OK:=False;
   For Loop:=0 to StrList.getCount-1 do
      If StrList.getStrings(Loop)<>LastIP then
         If StrList.getStrings(Loop)<>'' then Begin
            LastIP:=StrList.getStrings(Loop);
            If QueryZen(LastIP) then OK:=True;
         End;
   Result:=OK;
   StrList.Free;
End;

function emailGetDomain(email:string):string;
var
   I:Longint;

begin
   I:=Pos('@',email);
   If I>0 then
      If Copy(Email,I-1,1)='\' then Begin
         Delete(email,1,I);
         I:=Pos('@',email);
      End;
   If I>0 then result:=copy(email,I+1,255)
   Else Result:=''; // domain missing!
end;

function removeAngles(S:String):String;
begin
   if (pos('<',S)>0) and (pos('>',S)>0) then begin
      Delete(S,1,Pos('<',S));
      Delete(S,Pos('>',S),Length(S));
   end;
   Result:=Lowercase(S);
end;

/***
// Returns True if the email address is valid
// Author: Ernesto DSpirito
const
   // Valid characters in an "atom"
//   atom_chars = [#33..#255] - ['(',')','<','>','@',',',';',':','\','/','"','.','[',']',#127];
   atom_chars = ['!','#','$','%',"'",'*','+',',','-','.'];
   // Valid characters in a quoted-string
   //quoted_string_chars = [#0..#255] - ['"',#13,'\'];
   quoted_string_chars = [' '..'~'];
   // Valid characters in a subdomain
   letters=['A'..'Z','a'..'z'];
   letters_digits=['0'..'9','A'..'Z','a'..'z'];
   subdomain_chars=['-','0'..'9','A'..'Z','a'..'z'];

type
   States=(_BEGIN,_ATOM,_QTEXT,_QCHAR,_QUOTE,_LOCAL_PERIOD,_EXPECTING_SUBDOMAIN,_SUBDOMAIN,_HYPHEN);

function ValidEmail(email:string):boolean;
var
   State:States;
   i,n,subdomains:integer;
   c:char;

begin
   State:=_BEGIN;
   n:=Length(email);
   i:=1;
   subdomains := 1;
   while (i<=n) do begin
      c:=email[i];
      case State of
         _BEGIN:if c in atom_chars then State:=_ATOM
                else if c='"' then State:=_QTEXT
                else break;
         _ATOM:if c='@' then State:=_EXPECTING_SUBDOMAIN
               else if c='.' then State:=_LOCAL_PERIOD
               else if not (c in atom_chars) then break;
         _QTEXT:if c='\' then State:=_QCHAR
                else if c='"' then State:=_QUOTE
                else if not (c in quoted_string_chars) then break;
         _QCHAR:State:=_QTEXT;
         _QUOTE:if c='@' then State:=_EXPECTING_SUBDOMAIN
                else if c='.' then State:=_LOCAL_PERIOD
                else break;
         _LOCAL_PERIOD:if c in atom_chars then State:=_ATOM
                       else if c='"' then State:=_QTEXT
                       else break;
         _EXPECTING_SUBDOMAIN:if c in letters then State:=_SUBDOMAIN
                              else break;
         _SUBDOMAIN:if c='.' then begin
                       inc(subdomains);
                       State:=_EXPECTING_SUBDOMAIN;
                    end
                    else if c='-' then State:=_HYPHEN
                    else if not (c in letters_digits) then break;
         _HYPHEN:if c in letters_digits then State:=_SUBDOMAIN
                 else if c<>'-' then break;
      end;
      inc(i);
   end;
   if i<=n then Result:=False
   else Result:=(State=_SUBDOMAIN) and (subdomains>=2);
end;
***/

Procedure ProcessLine(var OP:opStates;S:String);
var
   Ws,Ts,Ss,Cmd:String;
   Field:TField;

Begin
   Log(S);
   Ws:=S;
   Cmd:=Uppercase(Fetch(S));
   Ss:=Fetch(S);
   Case OP of

      osReady:Begin
         if (copy(Cmd,3,2)='LO') then HelloStr:=Ws;
         If (Ss<>'') then begin
            If (Cmd=='HELO') then OP:=osHello
            else If (Cmd=='EHLO') then OP:=osHello;
            If OP=osHello then begin

               If Session.getLocalPort=25 then
                  If not QueryZen(Session.getPeerIPAddress) then Begin
                     Log('HELORBL Failed for IP:'+Session.getPeerIPAddress);
                     Session.Writeln('501 RBL Blocked');
                     OP:=osIgnore;
                     BlacklistDBF.Init(Nil);
                     BlacklistDBF.setFilename(ScriptRoot+'data/blacklist.dbf');
                     IndexFiles:=BlacklistDBF.getIndexFiles;
                     IndexFiles.Add(ScriptRoot+'data/blacklist.cdx');
                     BlacklistDBF.Open;
                     BlacklistDBF.setIndexTag('PK');
                     BlacklistDBF.Append;
                     Field:=BlacklistDBF.getFieldByName('IPADDR');
                     Field.setAsString(Session.getPeerIPAddress);
                     Field:=BlacklistDBF.getFieldByName('ADDEDON');
                     Field.setAsInteger(Timestamp);
                     BlacklistDBF.Post;
                     BlacklistDBF.Close;
                     BlacklistDBF.Free;
                     Exit;
                  End;

               If (Cmd=='EHLO') then Ts:='250-'
               Else Ts:='250 ';

               If (Pos('.',Ss)>0) then begin
                  If (Copy(Ss,1,1)='[') and (Copy(Ss,Length(Ss),1)=']') then Begin
                     Ss:=Copy(Ss,2,Length(Ss)-2);
                     Ws:=Ts+DefaultDomain+' '+Ss+' is '+Session.getPeerIPAddress;
                  End
                  Else Begin
                     Ws:=Session.GetIPAddressByHost(Ss,1);
                     If (Ws<>Session.getPeerIPAddress) then
                        Ws:=Ts+'Your IP '+Session.getPeerIPAddress+' is different from '+Ss+' IP of '+Ws
                     else
                        Ws:=Ts+DefaultDomain+' logged your IP '+Session.getPeerIPAddress;
                  End;
               End
               Else Ws:=Ts+DefaultDomain;
               Session.Writeln(Ws);

               If (Ts='250-') then begin
                  Session.Writeln(Ts+'SIZE 14680064');
                  Session.Writeln(Ts+'PIPELINING');
                  Ws:='250 AUTH LOGIN PLAIN';
                  Session.Writeln(Ws);
               End;
            End
            Else Begin
               Ws:='502 5.5.2 Error: command not recognized.';
               Session.Writeln(Ws);
            End;
         End

         Else Begin
            If (Cmd='HELO') then begin
               Ws:='501 Syntax: HELO hostname';
               Session.Writeln(Ws);
            End
            Else If (Cmd='EHLO') then begin
               Ws:='501 Syntax: EHLO hostname';
               Session.Writeln(Ws);
            End

            Else If (Cmd='RSET') then begin
               If Copy(Username,1,5)<>'root@' then begin
                  Username:='';
                  Password:='';
                  Authenticated:=False;
                  MailFrom:='';
                  MailFromDomain:='';
                  MailFromKnown:=False;
               End;
               RcptTo:='';
               RcptToDomain:='';
               RcptToKnown:=False;
               DataHeader:='';
               DataBody:='';
               OP:=osHello;
               Ws:='250 2.0.0 OK.';
               Session.Writeln(Ws);
            End

            else If (Ws='QUIT') then begin
               OP:=osBye;
               Ws:='221 2.0.0 Bye';
               Session.Writeln(Ws);
            End
            Else Begin
               Ws:='502 5.5.3 Error: command not recognized';
               Session.Writeln(Ws);
            End;
         End;

      End;

      osAUTHPlain:Begin
         If (UserName<>'') then Begin
            Password:=Ss;
// if found //
            Ws:='250 Ok welcome '+Username;
            Session.Writeln(Ws);
            OP:=osToFrom;
         End
         Else Begin
            UserName:=StringReplace(Ss,'#','@',[rfReplaceAll]);
            Ws:='334 '; // wait for password
            Session.Writeln(Ws);
         End;
      End;

      osAUTHLogin:Begin
         If (UserName<>'') then Begin
            Password:=Base64ToStr(Ss);
// if found //
            Ws:='250 Ok welcome '+Username;
            Session.Writeln(Ws);
            OP:=osToFrom;
         End
         Else Begin
            UserName:=StringReplace(Base64ToStr(Ss),'#','@',[rfReplaceAll]);
            Ws:='334 UGFzc3dvcmQ6'; // wait for password
            Session.Writeln(Ws);
         End;
      End;

      osHello,osToFrom:Begin
         If (Cmd='RSET') then begin
            If Copy(Username,1,5)<>'root@' then begin
               Username:='';
               Password:='';
               Authenticated:=False;
               MailFrom:='';
               MailFromDomain:='';
               MailFromKnown:=False;
            End;
            RcptTo:='';
            RcptToDomain:='';
            RcptToKnown:=False;
            DataHeader:='';
            DataBody:='';

            OP:=osHello;
            Ws:='250 2.0.0 OK.';
            Session.Writeln(Ws);
         End

         else If (Cmd='QUIT') then begin
            OP:=osBye;
            Ws:='221 2.0.0 Bye';
            Session.Writeln(Ws);
         End

         Else if (Cmd='AUTH') then begin
            If (Ss='PLAIN') then Begin
               OP:=osAUTHPlain;
               If (S='') then Begin
                  Ws:='334 '; // ready for userID
                  Session.Writeln(Ws);
               End
               Else Begin // sent:AUTH PLAIN username
                  Ws:=Base64ToStr(S);
                  Fetch(Ws,#0); // Account ID
                  Username:=StringReplace(Lowercase(Fetch(Ws,#0)),'#','@',[rfReplaceAll]);
                  Password:=Ws;
                  UsersDBF.Init(Nil);
                  UsersDBF.setFilename(ScriptRoot+'data/'+emailGetDomain(Username)+'/users.dbf');
                  IndexFiles:=UsersDBF.getIndexFiles;
                  IndexFiles.Add(ScriptRoot+'data/'+emailGetDomain(Username)+'/users.cdx');
                  UsersDBF.Open;
                  UsersDBF.setIndexTag('PK');
                  If UsersDBF.Find(Username,True,False) then begin
                     Field:=UsersDBF.getFieldByName('PWDHASH');
                     Authenticated:=Field.GetAsString=SHA1(Password);
                  End;
                  UsersDBF.Close;
                  UsersDBF.Free;
                  if Authenticated then Ws:='250 Authenticated OK'
                  else Ws:='500 Invalid Credentials.';
                  Session.Writeln(Ws);
                  OP:=osToFrom;
               End;
            End

            Else if (Ss='LOGIN') then Begin
               OP:=osAUTHLogin;
               If (S='') then Begin
                  Ws:='334 VXNlcm5hbWU6'; // ready for UserID
                  Session.Writeln(Ws);
               End
               Else Begin // sent:AUTH LOGIN username
                  UserName:=Base64toStr(S);
                  Ws:='334 UGFzc3dvcmQ6'; // ready for password //
                  Session.Writeln(Ws);
               End;
            End

            Else Begin
               Ws:='504 Unrecognized authentication type.';
               Session.Writeln(Ws);
            End;
         End

         Else if (Cmd='MAIL') then begin
            Fetch(Ws,':');
            If (Copy(Ws,1,2)<>'<>') or (Username='') then begin
               MailFrom:=RemoveAngles(Trim(Ws));
               MailFromDomain:=emailGetDomain(MailFrom); // to do RBL check!
            End;
            If MailFromDomain='' then Ws:='500 Invalid sender domain.'
            else begin
               Ws:=Copy(Trim(Ws),Pos('>',Trim(Ws)),255);
               If Ws<>'' then begin // could have SIZE=#### and AUTH=<mail from>
                  If Pos('AUTH=',Ws)>0 then begin
                     Delete(Ws,1,Pos('AUTH=',Ws)+4);
                     Ws:=RemoveAngles(Trim(Ws));
                     If (MailFrom==Ws) then begin
                        Username:=Ws;
                        if Copy(Username,1,5)='root@' then Ws:='250 2.2.0 Sender <'+MailFrom+'> OK'
                        else Ws:='432 4.7.12  A password transition is needed';
                     End
                     Else Ws:='534 5.7.9  Authentication mechanism is too weak';
                  End;
               End
               else Ws:='250 2.1.0 Sender <'+MailFrom+'> OK';
            end;
            Log(Ws);
            Session.Writeln(Ws);
         end

         else if (Cmd='RCPT') then begin
            If (MailFrom=='') then begin
               Ws:='503 5.5.1 Error: need MAIL command.';
               Session.Writeln(Ws);
            End
            Else Begin
               Fetch(Ws,':');
               RcptTo:=RemoveAngles(Trim(Ws));
               RcptToDomain:=emailGetDomain(RcptTo); // to do RBL check!
               If RcptToDomain='' then Ws:='500 Invalid recipient domain.'
               else Begin
                  DomainsDBF.Init(Nil);
                  DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
                  IndexFiles:=DomainsDBF.getIndexFiles;
                  IndexFiles.Add(ScriptRoot+'data/domains.cdx');
                  DomainsDBF.Open;
                  DomainsDBF.setIndexTag('PK');
                  MailFromKnown:=DomainsDBF.Find(MailFromDomain,True,False);  //Pos('@'+MailFromDomain+'@',knowndomains)>0;
                  RcptToKnown:=DomainsDBF.Find(RcptToDomain,True,False);      //Pos('@'+RcptToDomain+'@',knowndomains)>0;
                  DomainsDBF.Close;
                  DomainsDBF.Free;
                  If RcptToKnown or MailFromKnown then Begin
                     If MailFromKnown then begin
                        If not Authenticated then Ws:='553 5.7.1 <'+MailFrom+'>: Sender address rejected: not logged in'
                        else Ws:='250 2.1.6 Recipient <'+RcptTo+'> OK';
                     End
                     else Ws:='250 2.1.5 Recipient <'+RcptTo+'> OK';
                  End
                  Else Begin
                     If Authenticated then Begin
                        Log('* domains.dbf no hit for: '+MailFromDomain+', nor: '+RcptToDomain);
                     End;
                     RelayCache.Init(Nil);
                     RelayCache.setFilename(ScriptRoot+'data/relaycache.dbf');
                     IndexFiles:=RelayCache.getIndexFiles;
                     IndexFiles.Add(ScriptRoot+'data/relaycache.cdx');
                     RelayCache.Open;
                     RelayCache.setIndexTag('PK');
                     If RelayCache.Find(Session.getPeerIPAddress,True,False) then Begin
                        RelayCache.Edit;
                        Field:=RelayCache.getFieldByName('TRIES');
                        Field.setAsInteger(Field.getAsInteger+1);
                     end
                     Else Begin
                        RelayCache.Append;
                        Field:=RelayCache.getFieldByName('TRIES');
                        Field.setAsInteger(1);
                        Field:=RelayCache.getFieldByName('IPADDR');
                        Field.setAsString(Session.getPeerIPAddress);
                     End;
                     RelayCache.Post;
                     RelayCache.Close;
                     RelayCache.Free;
                     Ws:='554 Sender nor Recipient are known, no relay.';
                  End;
               End;
               Session.Writeln(Ws);
            End;
         end

         else if (Cmd='DATA') then begin
            CollectingHeader:=True;
            If (RcptTo=='') then begin
               Ws:='503 5.5.1 Error: need RCPT command.';
               Session.Writeln(Ws);
            End
            Else begin
               If not MailFromKnown then Begin
                  If not RBLPassed then begin
                     Ws:='500 Failed to pass RBL inspection, rejected.';
                     Session.Writeln(Ws);
                  End
                  Else Begin
                     If RcptToKnown then begin
                        OP:=osData;
                        Ws:='354 End data with <CR><LF>.<CR><LF>';
                     end
                     else Ws:='554 we do not relay email.';
                     Session.Writeln(Ws);
                  End;
               End
               Else Begin
                  OP:=osData;
                  Ws:='354 End data with <CR><LF>.<CR><LF>';
                  Session.Writeln(Ws);
               End;
            End;
         end

         else begin
            Ws:='500 unknown or unexpected command '+S;
            Session.Writeln(Ws);
         End;

      End;
   End;
End;

Function SerialNo:String;
var
   phase1:longword;
   rslt:longword;

begin
   If GetLocalTimeOffset<0 then begin
      Phase1:=(abs(GetLocalTimeOffset) div 60);
   end
   else begin
      Phase1:=(GetLocalTimeOffset div 60)+12;
   End;
   Result:=Numbering[Phase1 mod 36]+Numbering[OSValue];
   Phase1:=(((GetYears(Timestamp)-2000)*DayOfYear(Timestamp)*
      (GetHours(Timestamp)*24)*(GetMinutes(Timestamp)*60))+
      GetSeconds(Timestamp));
   Rslt:=Trunc(phase1 / Pass5);
   Result+=Numbering[(Rslt mod 36)+1];
   Phase1-=Rslt*Pass5;
   Rslt:=Trunc(phase1 / Pass4);
   Result+=Numbering[(Rslt mod 36)+1];
   Phase1-=Rslt*Pass4;
   Rslt:=Trunc(phase1 / Pass3);
   Result+=Numbering[(Rslt mod 36)+1];
   Phase1-=Rslt*Pass3;
   Rslt:=Trunc(phase1 / Pass2);
   Result+=Numbering[(Rslt mod 36)+1];
   Phase1-=Rslt*Pass2;
   Rslt:=Trunc(phase1 / Pass1);
   Result+=Numbering[(Rslt mod 36)+1];
   Phase1-=Rslt*Pass1;
   Result+=Numbering[(Phase1 mod 36)+1];
end;

Procedure Main;
var
   Ws:String;
   OP:opStates;
   Timeout:TTimestamp;
   Field:TField;

Begin
   InitLog(ScriptRoot+'logs/smtpserver'+IntToStr(Session.getLocalPort)+'.log');

// 72hr Block Check:
   RelayCache.Init(Nil);
   RelayCache.setFilename(ScriptRoot+'data/relaycache.dbf');
   IndexFiles:=RelayCache.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/relaycache.cdx');
   RelayCache.Open;
   RelayCache.setIndexTag('PK');
   If RelayCache.Find(Session.getPeerIPAddress,True,False) then Begin
      Field:=RelayCache.getFieldByName('TRIES');
      If Field.getAsInteger>=3 then begin
         Ws:='221 '+defaultdomain+' SMTPServer auto-blacklist goodbye.';
         Log(Ws);
         Session.Writeln(Ws);
         DoneLog;
         RelayCache.Close;
         RelayCache.Free;
         Exit;
      End;
   End;
   RelayCache.Close;
   RelayCache.Free;

// Permanent Block Check:
   BlacklistDBF.Init(Nil);
   BlacklistDBF.setFilename(ScriptRoot+'data/blacklist.dbf');
   IndexFiles:=BlacklistDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/blacklist.cdx');
   BlacklistDBF.Open;
   BlacklistDBF.setIndexTag('PK');
   If BlacklistDBF.Find(Session.getPeerIPAddress,True,False) then begin
      Log('Black List Match for IP:'+Session.getPeerIPAddress);
      Session.Writeln('221 '+defaultdomain+' blacklisted IP Ignored.');
      DoneLog;
      BlacklistDBF.Close;
      BlacklistDBF.Free;
      Exit;
   End;
   BlacklistDBF.Close;
   BlacklistDBF.Free;

try
   Ws:='220 '+defaultdomain+':'+IntToStr(Session.getLocalPort)+' SMTPServer (ModernPascal) script ready.';
   Log(Ws);
   Session.Writeln(Ws);
   OP:=osReady;
   Timeout:=Timestamp+180;
   while Session.Connected do begin
      If Session.Readable then begin
         If Session.CountWaiting=0 then break; // OOB disconnect SYN packet
         Timeout:=Timestamp+180;
         Ws:=Session.Readln(500);
         if (OP<>osData) then ProcessLine(OP,Ws)
         else Begin
            //Log('D:'+Ws);
            if CollectingHeader then begin
               If Ws<>'' then DataHeader+=Ws+#13#10
               Else CollectingHeader:=False;
            end
            else begin
               If Ws<>'.' then DataBody+=Ws+#13#10;
            end;
            If (Ws='.') then begin
               DataHeader:='Received: from '+Session.getPeerIPAddress+' ('+HelloStr+') ('+RcptTo+')'+#13#10+
                  ' by '+DefaultDomain+' using SMTPServer (ModernPascal); '+
                     FormatTimestamp('DD MMM YYYY HH:MM:SS ',Timestamp)+'-0500'+#13#10+DataHeader+
                  'X-TCPREMOTEIP: '+Session.getPeerIPAddress+#13#10;
               If RcptToKnown then begin
                  CreateDirEx(ScriptRoot+'inbox/'+RcptToDomain+'/'+RcptTo+'/Inbox/');
                  DataHeader:='Delivered to: '+RcptTo+#13#10+DataHeader;
                  SaveToFile(ScriptRoot+'inbox/'+RcptToDomain+'/'+RcptTo+'/Inbox/'+SerialNo,DataHeader+#13#10+DataBody);
               End
               Else Begin
                  SaveToFile(ScriptRoot+'outbound/'+SerialNo,DataHeader+#13#10+DataBody);
               End;
               Ws:='250 2.0.0 OK: queued as '+SerialNo;
               Log(Ws);
               Session.Writeln(Ws);
               // Clear Variables //
               OP:=osReady;
            End;
         End;
         If (OP=osBye) then Break;
      end
      else Yield(10);
      If Timeout<Timestamp then begin
         Ws:='421 4.4.2 '+defaultdomain+' Error: timeout exceeded.';
         Log(Ws);
         Session.Writeln(Ws);
         Session.Disconnect;
         Break;
      End;
   end;
finally
   DoneLog;
end;
End;

Begin
   // Make sure you run mkdbfs before starting coderunner for the mail servers!
   ScriptRoot:=ExtractFilePath(ExecFilename);
   Main;
End.
