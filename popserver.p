Program POPServer.v1170411;

/////////////////////////////////////////////////////////////////////////////
// Script Name: popserver.p
//   Author(s): G.E. Ozz Nixon Jr.
//   Copyright: (c) 2017 by MP Solutions, LLC.
/////////////////////////////////////////////////////////////////////////////
// STILL IN DEVELOPMENT!
// ==========================================================================
// Implements: RFC1081, RFC1734, RFC1939, RFC2449
// Implements: http://www.pop4.org/pop4/pop4spec.html
// Defenses:
/////////////////////////////////////////////////////////////////////////////
// DISABLED: APOP, would require us to store the password locally, we do not!
/////////////////////////////////////////////////////////////////////////////

uses
   display, math, classes, strings, environment, datetime, databases,
   hashes, compression;

const
   defaultdomain='ip-132-148-27-199.ip.secureserver.net'; // REVERSE PTR

{$I /BBS/includes/logging.i}

type
   statrec = packed record
      actualfilename:string;
      filename:string;
      filesize:longword;
   end;

var
   ScriptRoot:String;
   MD5Seed:String;
   BlacklistDBF:THalcyonDataset; // TO-IMPLEMENT //
   SystemDBF:THalcyonDataset;
   UsersDBF:THalcyonDataset;
   IndexFiles:TStringList;
   Field:TField;
   Username:String;
   Authenticated:Boolean;
   statarray:Array of StatRec;
   InboxPath:String;
   InboxMsgs:Longword;
   InboxBytes:Longword;
   LastTouched:Longword;

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

function OpenDatabases(domain:string):boolean;
begin
   If not FileExists(ScriptRoot+'data/'+domain+'/users.dbf') then Result:=False
   Else Begin
      SystemDBF.Init(Nil);
      SystemDBF.setFilename(ScriptRoot+'data/'+domain+'/system.dbf');
      SystemDBF.Open;
      Field:=SystemDBF.getFieldByName('ACTIVE');
      If Field.getAsBoolean then begin
         UsersDBF.Init(Nil);
         UsersDBF.setFilename(ScriptRoot+'data/'+domain+'/users.dbf');
         //Schema.Add('EMAIL,C,80,0');    // Email Address
         //Schema.Add('FNAME,C,35,0');    // First Name
         //Schema.Add('LNAME,C,35,0');    // Last Name
         //Schema.Add('PWDHASH,C,40,0');  // SHA-1 Hash of Password
         //Schema.Add('ACTIVE,L,1,0');    // Account Enabled
         //Schema.Add('DOMAIN,L,1,0');    // Domain Admin
         //Schema.Add('GLOBAL,L,1,0');    // Global Admin
         //Schema.Add('QUOTA,N,20,0');    // 0=Unlimited, MB of Disk Space Usage
         //Schema.Add('EMPLOYID,C,35,0'); // Employee ID
         //Schema.Add('DEPART,C,35,0');   // Department
         //Schema.Add('TITLE,C,35,0');    // Job Title
         //Schema.Add('MOBILE,C,20,0');   // Cell Phone #
         IndexFiles:=UsersDBF.getIndexFiles;
         IndexFiles.Add(ScriptRoot+'data/'+domain+'/users.cdx');
         UsersDBF.Open;
         UsersDBF.setIndexTag('PK');
         Result:=True;
      End
      Else Begin
         Log(Domain+' not set to active.');
         SystemDBF.Close;
         SystemDBF.Free;
         Result:=False;
      End;
   End;
End;

procedure inboxStat;
var
   SRec:SearchRec;
   Err:Longint;

Begin
   SetLength(StatArray,0);
   InboxMsgs:=0;
   InboxBytes:=0;
   Err:=FindFirst(InboxPath+{$IFDEF UNIX}'*'{$ELSE}'*.*'{$ENDIF},faAnyFile,SRec);
   While Err=0 do begin
      If not SearchRecIsDirectory(SRec) then begin
         SetLength(StatArray,Length(StatArray)+1);
         StatArray[High(StatArray)].ActualFilename:=SearchRecName(SRec);
         StatArray[High(StatArray)].Filename:=SearchRecName(SRec);
         StatArray[High(StatArray)].Filesize:=SearchRecSize(SRec);
         Inc(InboxMsgs);
         Inc(InboxBytes,SearchRecSize(SRec));
      End;
      Err:=FindNext(SRec);
   End;
   FindClose(SRec);
End;

Procedure ProcessLine(S:String);
Var
   Ws,Ts,Ss:String;
   Ctr:Longint;
   Loop:Longword;
   StrList:TStringList;
   InHeader:Boolean;

Begin
   Ws:=S;
   Log(Ws);
   Ts:=Uppercase(Fetch(S));
   If Ts='NOOP' then Session.Writeln('+OK')
   else If Ts='USER' then begin
      Username:='';
      Ss:=emailGetDomain(StringReplace(S,'#','@',[rfReplaceAll]));
      If Ss='' then Session.Writeln('-ERR never heard of '+S)
      Else Begin
         If OpenDatabases(Ss) then begin
            if UsersDBF.Find(StringReplace(S,'#','@',[rfReplaceAll]),True,False) then begin
               Field:=UsersDBF.getFieldByName('ACTIVE');
               If not Field.getAsBoolean then Session.Writeln('-ERR mailbox is disabled.')
               else begin
                  Session.Writeln('+OK');
                  Username:=StringReplace(S,'#','@',[rfReplaceAll]);
// inbox/fido.pwnz.org/admin\@fido.pwnz.org/
                  InboxPath:=ScriptRoot+'inbox/'+emailGetDomain(Username)+'/'+Username+'/';
               End;
            End
            else Session.Writeln('-ERR mailbox unknown.');
         End
         Else Session.Writeln('-ERR mailservice unknown.');
      End;
   end
   else If Ts='PASS' then begin
      If Username='' then Session.Writeln('-ERR mailbox not specified.')
      else begin
         Field:=UsersDBF.getFieldByName('PWDHASH');
         If (Field.getAsString=SHA1(S)) then begin
            Authenticated:=True;
            inboxStat;
            Session.Writeln('+OK mailbox has '+IntToCommaStr(InboxMsgs)+' messages ('+IntToCommaStr(InboxBytes)+' octets)');
         end
         else Session.Writeln('-ERR invalid password.');
      end;
   end
   else if Ts='STAT' then begin
      If Authenticated then begin
         inboxStat; // refresh //
         Session.Writeln('+OK '+IntToStr(InboxMsgs)+#32+IntToStr(InboxBytes));
      end
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='LIST' then begin
      If Authenticated then begin
         If (S='') then begin
            Session.Writeln('+OK '+IntToStr(InboxMsgs)+' messages ('+IntToStr(InboxBytes)+' octets).');
            For Loop:=1 to InboxMsgs do
               Session.Writeln(IntToStr(Loop)+#32+IntToStr(StatArray[Loop-1].Filesize));
            Session.Writeln('.');
         end
         else begin
            If (StrToIntDef(S,0)<1) or (StrToIntDef(S,0)>InboxMsgs) then Session.Writeln('-ERR no such message.')
            else begin
               LastTouched:=StrToIntDef(S,0);
               Session.Writeln('+OK '+S+#32+IntToStr(StatArray[LastTouched-1].Filesize));
            end;
         End;
      end
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='RETR' then begin
      If Authenticated then begin
         If (S='') then Session.Writeln('-ERR no message ID specified.')
         else If (StrToIntDef(S,0)<1) or (StrToIntDef(S,0)>InboxMsgs) then Session.Writeln('-ERR no such message.')
         else begin
            If (StatArray[StrToIntDef(S,0)-1].Filename<>'') then begin
               Session.Writeln('+OK');
               LastTouched:=StrToIntDef(S,0);
               LoadFromFile(InboxPath+StatArray[LastTouched-1].Filename,Ws);
               Session.Writeln(Ws);
               Session.Writeln('.');
            end
            Else Session.Writeln('-ERR you need to STAT the server again.');
         end;
      end
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='DELE' then begin
      If Authenticated then begin
         If (S='') then Session.Writeln('-ERR no message ID specified.')
         else If (StrToIntDef(S,0)<1) or (StrToIntDef(S,0)>InboxMsgs) then Session.Writeln('-ERR no such message.')
         else begin
            If (StatArray[StrToIntDef(S,0)-1].Filename<>'') then begin
               Session.Writeln('+OK message '+S+' deleted.');
               LastTouched:=StrToIntDef(S,0);
               StatArray[LastTouched-1].Filename:='';
            end
            Else Session.Writeln('-ERR message '+S+' already deleted.');
         end;
      end
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='LAST' then begin
      If Authenticated then Session.Writeln('+OK '+IntToStr(LastTouched))
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='RSET' then begin
      inboxStat;
      Session.Writeln('+OK '+IntToStr(InboxMsgs)+#32+IntToStr(InboxBytes));
   end
   else if Ts='TOP' then begin
      If Authenticated then begin
         Ss:=Fetch(S);
         If (Ss='') then Session.Writeln('-ERR no message ID specified.')
         else If (StrToIntDef(Ss,0)<1) or (StrToIntDef(Ss,0)>InboxMsgs) then Session.Writeln('-ERR no such message.')
         else begin
            If (StatArray[StrToIntDef(Ss,0)-1].Filename<>'') then begin
               If (S='') then Session.Writeln('-ERR number of lines not specified.')
               else begin
                  Ctr:=StrToIntDef(S,1);
                  Session.Writeln('+OK');
                  StrList.Init;
                  LastTouched:=StrToIntDef(Ss,0);
                  StrList.LoadFromFile(InboxPath+StatArray[LastTouched-1].Filename);
                  inHeader:=True;
                  For Loop:=0 to StrList.getCount-1 do begin
                     If inHeader then Begin
                        If StrList.getStrings(Loop)='' then inHeader:=False;
                        Session.Writeln(StrList.getStrings(Loop));
                     end
                     else begin
                        Session.Writeln(StrList.getStrings(Loop));
                        Dec(Ctr);
                        If Ctr<1 then break;
                     End;
                  End;
                  StrList.Free;
                  Session.Writeln('.');
               end;
            end
            Else Session.Writeln('-ERR no such message.');
         end;
      end
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='UIDL' then begin
      If Authenticated then begin
         If S='' then begin
            Session.Writeln('+OK unique-id listing follows');
            For Loop:=0 to Length(StatArray)-1 do begin
               If StatArray[Loop].Filename<>'' then
                  Session.Writeln(IntToStr(Loop+1)+#32+StatArray[Loop].ActualFilename);
            End;
            Session.Writeln('.');
         end
         else If (StrToIntDef(S,0)<1) or (StrToIntDef(S,0)>InboxMsgs) then Session.Writeln('-ERR no such message.')
         else begin
            Loop:=StrToIntDef(S,1)-1;
            If StatArray[Loop].Filename<>'' then begin
               Session.Writeln('+OK');
               Session.Writeln(IntToStr(Loop+1)+#32+StatArray[Loop].ActualFilename);
               Session.Writeln('.');
            End
            Else Session.Writeln('-ERR no such message');
         end;
      end
      else Session.Writeln('-ERR not authenticated.');
   end
   else if Ts='CAPA' then begin
      Session.Writeln('+OK Capability list follows'+#13#10+
         'TOP'+#13#10+'USER'+#13#10+'PIPELINING'+#13#10+'UIDL'+#13#10+'EXPIRE NEVER'+#13#10+'.');
   end
   Else Session.Writeln('-ERR Unknown command.');
End;

Procedure Main;
var
   Ws:String;
   Timeout:TTimestamp;
   Loop:Longword;

Begin
   InitLog(ScriptRoot+'logs/popserver'+IntToStr(Session.getLocalPort)+'.log');
   Log('Connected from '+Session.getPeerIPAddress);
   //MD5Seed:='<'+IntToStr(GetProcessID)+'.'+IntToStr(Timestamp)+'@'+defaultdomain+'>';
   Ws:='+OK POPServer:'+IntToStr(Session.getLocalPort)+' POP4 rev 0 (ModernPascal) ready '+MD5Seed;
   Session.Writeln(Ws);
   Timeout:=Timestamp+180;
   while Session.Connected do begin
      If Session.Readable then begin
         If Session.CountWaiting=0 then break; // OOB disconnect SYN packet
         Timeout:=Timestamp+180;
         Ws:=Session.Readln(500);
         If (Uppercase(Ws)='QUIT') then begin
            Session.Writeln('+OK Good-bye.');
            if Authenticated then begin
               For Loop:=0 to Length(StatArray)-1 do
                  if (StatArray[Loop].Filename='') then
                     DeleteFile(InboxPath+StatArray[Loop].ActualFilename);
               Setlength(StatArray,0);
            End;
            If Username<>'' then begin
               SystemDBF.Close;
               SystemDBF.Free;
               UsersDBF.Close;
               USersDBF.Free;
            End;
            Exit;
         End
         Else ProcessLine(Ws);
      End
      Else Yield(10);
      If Timeout<Timestamp then begin
         Ws:='-ERR Disconnected for inactivity.';
         Log(Ws);
         Session.Writeln(Ws);
         Session.Disconnect;
         Break;
      End;
   End;
End;

Procedure CreateDatabases;
var
   Schema:TStringList;
   Field:TField;
   Ws:String;

begin
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
end;

Begin
   ScriptRoot:=ExtractFilePath(ExecFilename);
   CreateDirEx(ScriptRoot+'data');
   CreateDirEx(ScriptRoot+'logs');
   CreateDirEx(ScriptRoot+'inbox');
   CreateDatabases;
   Main;
End.
