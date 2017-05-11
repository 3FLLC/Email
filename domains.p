Program Domains.DBCLITool;
{$H-}

uses
   classes,
   strings,
   environment,
   databases,
   display;

var
   ScriptRoot:String;
   Schema,IndexFiles:TStringList;
   DomainsDBF:THalcyonDataset;

Procedure ShowHelp;
Begin
   Writeln('usage: mp '+ScriptRoot+'domains.p');
   Writeln();
   Writeln('--list                displays all domains in database.');
   Writeln('--list domain         displays all users in domains database.');
   Writeln('--add domain          add the domain to the database.');
   Writeln('--del domain          remove the domain from the database.');
   Writeln('--find domain         find a domain to the database.');
   Writeln('--activate domain     enables domain to accept POP/IMAP.');
   Writeln('--deactivate domain   disables domain from accepting POP/IMAP.'); // 63
   Writeln('--enable full_login   enables domain user.');
   Writeln('--disable full_login  disables domain user.');
   Writeln('--pack                pack all deleted records in database.');
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

procedure ToggleDomainUser(S:String;Active:Boolean);
var
   Field:TField;
   SystemDBF:THalcyonDataset;
   UsersDBF:THalcyonDataset;
   D:String;

Begin
   S:=lowercase(StringReplace(S,'#','@',[rfReplaceAll]));
   D:=emailGetDomain(S);
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   If DomainsDBF.Find(D,True,False) then begin
      If (Active) then begin
         SystemDBF.Init(Nil);
         SystemDBF.setFilename(ScriptRoot+'data/'+D+'/system.dbf');
         SystemDBF.Open;
         SystemDBF.Edit;
         Field:=SystemDBF.getFieldByName('ACTIVE');
         Field.setAsBoolean(Active);
         SystemDBF.Post;
         Writeln('Updated domain.');
         SystemDBF.Close;
         SystemDBF.Free;
      End;
      UsersDBF.Init(Nil);
      UsersDBF.setFilename(ScriptRoot+'data/'+D+'/users.dbf');
      IndexFiles:=UsersDBF.getIndexFiles;
      IndexFiles.Add(ScriptRoot+'data/'+D+'/users.cdx');
      UsersDBF.Open;
      UsersDBF.setIndexTag('PK');
      If UsersDBF.Find(S,True,False) then begin
         UsersDBF.Edit;
         Field:=UsersDBF.getFieldByName('ACTIVE');
         Field.setAsBoolean(Active);
         UsersDBF.Post;
         Writeln('Updated '+S);
      End
      Else Writeln('No such user');
      UsersDBF.Close;
      UsersDBF.Free;
   End
   Else Writeln('Did not find ',D);
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure ToggleDomain(S:String;Active:Boolean);
var
   Field:TField;
   SystemDBF:THalcyonDataset;

Begin
   S:=lowercase(S);
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   If DomainsDBF.Find(S,True,False) then begin
      SystemDBF.Init(Nil);
      SystemDBF.setFilename(ScriptRoot+'data/'+S+'/system.dbf');
      SystemDBF.Open;
      SystemDBF.Edit;
      Field:=SystemDBF.getFieldByName('ACTIVE');
      Field.setAsBoolean(Active);
      SystemDBF.Post;
      Writeln('Updated domain.');
      SystemDBF.Close;
      SystemDBF.Free;
   End;
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure DelDomain(S:String);
var
   Field:TField;

Begin
   S:=lowercase(S);
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   If DomainsDBF.Find(S,True,False) then begin
      DomainsDBF.Delete;
      //DomainsDBF.Post;
   End;
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure FindDomain(S:String);
var
   Field:TField;

Begin
   S:=lowercase(S);
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   If not DomainsDBF.Find(S,True,False) then Writeln('not found')
   Else Writeln('found');
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure AddDomain(S:String);
var
   Field:TField;

Begin
   S:=lowercase(S);
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   If not DomainsDBF.Find(S,True,False) then begin
      DomainsDBF.Append;
      Field:=DomainsDBF.getFieldByName('DOMAIN');
      Field.setAsString(S);
      DomainsDBF.Post;
   End;
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure PackDomains;
var
   Field:TField;

Begin
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.setExclusive(True);
   //DomainsDBF.setReadOnly(True);
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   Writeln(DomainsDBF.getRecordCount,' rows, before.');
   DomainsDBF.Pack;
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure ListUsers(D:String);
var
   UsersDBF:THalcyonDataset;
   Field:TField;

Begin
   UsersDBF.Init(Nil);
   UsersDBF.setFilename(ScriptRoot+'data/'+D+'/users.dbf');
   IndexFiles:=UsersDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/'+D+'/users.cdx');
   UsersDBF.Open;
   UsersDBF.setIndexTag('PK');
   While not DomainsDBF.getEOF do begin
      Field:=UsersDBF.getFieldByName('EMAIL');
      Write(PadRight(Field.getAsString,50));
      Field:=UsersDBF.getFieldByName('ACTIVE');
      If Field.getAsBoolean then Writeln('Active')
      Else Writeln('Inactive');
      UsersDBF.Next;
   End;
   Writeln('');
   Writeln(UsersDBF.getRecordCount,' rows.');
   UsersDBF.Close;
   UsersDBF.Free;
End;

procedure ListDomains;
var
   Field:TField;

Begin
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   IndexFiles:=DomainsDBF.getIndexFiles;
   IndexFiles.Add(ScriptRoot+'data/domains.cdx');
   DomainsDBF.Open;
   DomainsDBF.setIndexTag('PK');
   While not DomainsDBF.getEOF do begin
      Field:=DomainsDBF.getFieldByName('DOMAIN');
      Writeln(Field.getAsString);
      DomainsDBF.Next;
   End;
   Writeln('');
   Writeln(DomainsDBF.getRecordCount,' rows.');
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

procedure CreateDatabases;
Begin
   DomainsDBF.Init(Nil);
   DomainsDBF.setFilename(ScriptRoot+'data/domains.dbf');
   If not FileExists(ScriptRoot+'data/domains.dbf') then begin
      Schema.Init;
      Schema.Add('DOMAIN,C,65,0');
      DomainsDBF.createDBF(ScriptRoot+'data/domains.dbf','',FoxPro,Schema);
      Schema.Free;
      DomainsDBF.Open;
      DomainsDBF.IndexOn(ScriptRoot+'data/domains.cdx','PK','DOMAIN','.NOT.DELETED()',Unique,Ascending);
   End;
   DomainsDBF.Close;
   DomainsDBF.Free;
End;

Begin
   ScriptRoot:=ExtractFilePath(ExecFilename);
   CreateDirEx(ScriptRoot+'data');
   CreateDatabases;
   Writeln('Email Server Domains Database CLI Tool');
   Writeln();
   If Paramcount<2 then ShowHelp
   else if Paramstr(Paramcount)=='--list' then ListDomains
   else if Paramstr(Paramcount)=='--pack' then PackDomains
   else if Paramstr(Paramcount-1)=='--list' then ListUsers(Paramstr(Paramcount))
   else if Paramstr(Paramcount-1)=='--activate' then ToggleDomain(Paramstr(Paramcount),True)
   else if Paramstr(Paramcount-1)=='--deactive' then ToggleDomain(Paramstr(Paramcount),False)
   else if Paramstr(Paramcount-1)=='--enable' then ToggleDomainUser(Paramstr(Paramcount),True)
   else if Paramstr(Paramcount-1)=='--disable' then ToggleDomainUser(Paramstr(Paramcount),False)
   else if Paramstr(Paramcount-1)=='--find' then FindDomain(Paramstr(Paramcount))
   else if Paramstr(Paramcount-1)=='--add' then AddDomain(Paramstr(Paramcount))
   else if Paramstr(Paramcount-1)=='--del' then DelDomain(Paramstr(Paramcount));
end.
