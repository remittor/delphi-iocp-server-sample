unit uHPServClient;

(*******************************************************************************

Author: Sergey N. Naberegnyh

Created: August, 05, 2008
Updated: January, 23, 2009

// Cmd.exe -> netsh winsock reset    ???

*******************************************************************************)

interface

uses
  Windows, Messages, SysUtils, Classes,
  HPSockApi, HPScktSrvr, WinSock; // JwaWinCrypt;

type
  THttpMethod = (METHOD_UNKNOWN, METHOD_GET, METHOD_HEAD);
  TAuthType   = (atNone, atBasic, atDigest);

  EDigestAuthInitError = Exception;

  TNonceCountMask = array[0..7] of Cardinal;
  PNonceCountMask = ^TNonceCountMask;

  TStringList = Class(Classes.TStringList);

  TNonceBuffer = packed record
    Timestamp: TSystemTime;
    Hash: array[0..31] of Byte;
  end;

  THttpSrvClient = class(THPServerClient)
  private
    FClientID: Cardinal;
    FNotProcessed: integer;
    FCmdAccepted: boolean;
    FHttpMethod: THttpMethod;
    FVersion, FObjName, FParams: AnsiString;
    FRequest: TStringList;
    FResponse: AnsiString;
    FFile: THandle;
    FkeepAlive: boolean;

    function BuildAuthResponse(const sNonce: AnsiString): AnsiString;
    procedure ParseCmdLine(const CommandLine: AnsiString);
    procedure SendError(ErrCode: integer; const sAuthInfo: AnsiString = '');

    procedure ProcessRequest();

    function CheckUserPassword(const Auth: AnsiString): boolean;
  protected
    FAuthorized: boolean;
    FAuthType: TAuthType;
    procedure SendResponse(PData: Pointer; DataLen: integer); virtual;
    procedure SendResponse2(PData: Pointer; DataLen: integer); virtual;
    procedure CloseFile;
    property FileHandle: THandle read FFile;
  public
    constructor Create(); override;
    destructor Destroy; override;
    procedure Initialize; virtual;
    procedure Finalize; virtual;
    procedure DoWriteComplete(BytesTransfered: Cardinal; CompletionKey, Error: Integer); virtual;
    procedure ProcessBuffer(PBuf: PAnsiChar; BufLen: integer); virtual;
    property KeepAlive: boolean read FkeepAlive write FKeepAlive;
    property RequestHeader: TStringList read FRequest;
    property ClientID: Cardinal read FClientID;
  end;

var
  ClientIDs: Cardinal = 0;

implementation

uses
  uHPServCon, StrUtils, Math;

const
  cOpaque               = '07D0A5F7D91D43DBB30C0211F9FFDB3C';
  Current_Zone          = 'localhost zone';
  MICROSOFT_DIGEST_NAME = 'Microsoft Digest Security Protocol Provider';
  WDIGEST_SP_NAME       = 'WDigest';
  Session_Timeout = 5/(24 * 60);
  
function DecodeBase64(pSource: Pointer; SourceLen: DWORD; pDest: Pointer; var DestLen: DWORD): BOOL;
const
  BBase64: array [0..79] of Byte =
    ($3E, $40, $40, $40, $3F, $34, $35, $36, $37, $38,
     $39, $3A, $3B, $3C, $3D, $40, $40, $40, $40, $40,
     $40, $40, $00, $01, $02, $03, $04, $05, $06, $07,
     $08, $09, $0A, $0B, $0C, $0D, $0E, $0F, $10, $11,
     $12, $13, $14, $15, $16, $17, $18, $19, $40, $40,
     $40, $40, $40, $40, $1A, $1B, $1C, $1D, $1E, $1F,
     $20, $21, $22, $23, $24, $25, $26, $27, $28, $29,
     $2A, $2B, $2C, $2D, $2E, $2F, $30, $31, $32, $33);
var
  i, k, d, dd, Len: DWORD;
  b: byte;
  PD, PS: PAnsiChar;
begin
  Result:= (@DestLen <> nil) and (pSource <> nil);
  if not Result then begin
    SetLastError(ERROR_INVALID_PARAMETER);
    Exit;
  end;

  Len:= (SourceLen div 4) * 3 + (SourceLen mod 4);
  if (pDest = nil) or (Len = 0) then begin
    DestLen:= Len;
    Exit;
  end;

  if Len > DestLen then begin
    Result:= false;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    Exit;
  end;

  i:= 0; d:= 0; dd:= 0;
  PD:= pDest; PS:= pSource;

  repeat
    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then begin
      Inc(i);
      Continue;
    end;
    PD[d]:= Chr(Ord(b) shl 2);
    dd:= 1;
    Inc(i); Inc(d);
    if i >= SourceLen then Break;

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then begin
      Inc(i);
      Continue;
    end;
    PD[d - 1]:= Chr(Ord(PD[d - 1]) or ((b shr 4) and 3));
    PD[d]:= Chr((b shl 4) and $F0);
    Inc(i); Inc(d);
    if i >= SourceLen then Break;

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then begin
      Inc(i);
      Continue;
    end;
    PD[d - 1]:= Chr(Ord(PD[d - 1]) or ((b shr 2) and $0F));
    PD[d]:= Chr((b shl 6) and $FC);
    Inc(i); Inc(d);
    if i >= SourceLen then Break;

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then begin
      Inc(i);
      Continue;
    end;
    PD[d - 1]:= Chr(Ord(PD[d - 1]) or (b and $3F));
    Inc(i); dd:= 0;
  until i >= SourceLen;

  DestLen:= d - dd;
end;

function DecodeBase64Str(const Source: AnsiString): AnsiString;
var
  L, L2: Cardinal;
begin
  Result := '';
  if Source = '' then Exit;
  if not DecodeBase64(@Source[1], Length(Source), nil, L) then Exit;
  Setlength(Result, L);
  L2 := L;
  if not DecodeBase64(@Source[1], Length(Source), @Result[1], L) then begin
    Result := '';
  end else begin
    if L2 <> L then SetLength(Result, L);
  end;
end;

function BinToHex(Buffer: PByteArray; BufSize: Integer): AnsiString;
const
  Convert: array[0..15] of Char = '0123456789abcdef';
var
  I: Integer;
  P: PAnsiChar;
begin
  SetLength(Result, BufSize * 2);
  P:= PAnsiChar(result);
  for I := 0 to BufSize - 1 do begin
    P[0] := Convert[Byte(Buffer[I]) shr 4];
    P[1] := Convert[Byte(Buffer[I]) and $F];
    Inc(P, 2);
  end;
end;

{ THttpSrvClient }

function THttpSrvClient.BuildAuthResponse(const sNonce: AnsiString): AnsiString;
const
  cDigestAuth = 'WWW-Authenticate: Digest realm="localhost zone",' +
                ' qop="auth",' +
                ' nonce="%s", opaque="%s"';
begin
  Result := Format(cDigestAuth, [sNonce, cOpaque]);
end;

function THttpSrvClient.CheckUserPassword(const Auth: AnsiString): boolean;
var
  k: integer;
  ds, Usr, Psw: AnsiString;
begin
  Result:= false;
  ds:= DecodeBase64Str(Auth);
  k:= Pos(':', ds);
  if k < 1 then exit;
  Usr:= UpperCase(Copy(ds, 1, k - 1));
  Psw:= Copy(ds, k + 1, 255);
  Result:= (Usr = 'TEST_USER') and (Psw = 'mypsw');
end;

procedure THttpSrvClient.CloseFile;
begin
  if FFile <> 0 then begin
    CloseHandle(FFile);
    FFile:= 0;
  end;
end;

constructor THttpSrvClient.Create;
begin
  inherited;
  //Inc(ClientIDs);
  //FClientID := ClientIDs;
  Integer(FClientID) := Windows.InterlockedIncrement(Integer(ClientIDs));
  FRequest := TStringList.Create;
  FRequest.Sorted := True;
end;

destructor THttpSrvClient.Destroy;
begin
  Finalize;
  FRequest.Free;
  inherited;
end;

procedure THttpSrvClient.DoWriteComplete(BytesTransfered: Cardinal; CompletionKey, Error: Integer);
var
  WsaBuf: TWsaBuf;
begin
  CloseFile;
  FResponse := '';
  if KeepAlive then begin
    WsaBuf.cLength := BufferSize;
    WsaBuf.pBuffer := Buffer;
    if Read(WsaBuf, 1, 0) <> 0 then Disconnect;
  end else begin
    Disconnect;
  end;  
end;

procedure THttpSrvClient.Finalize;
begin
  FRequest.Clear;
  CloseFile;
end;

procedure THttpSrvClient.Initialize;
begin
  FNotProcessed:= 0;
  FCmdAccepted:= false;
  FkeepAlive:= false;
  FAuthorized:= false;
  FAuthType:= atNone;// atDigest; // 
  FVersion:= ''; FObjName:= ''; FParams:= '';
end;

procedure THttpSrvClient.ParseCmdLine(const CommandLine: AnsiString);
var
  Command: AnsiString;
  i, L, n: integer;
begin
  Server.LogMsg(1, 1, ClientID, 'ParseCmdLine - Line '+CommandLine);
  FHttpMethod:= METHOD_UNKNOWN;
  i:= Pos(' ', CommandLine);
  if i = 0 then exit;
  Command:= Copy(CommandLine, 1, i - 1);
  if Command = 'GET' then FHttpMethod:= METHOD_GET else
  if Command = 'HEAD' then FHttpMethod:= METHOD_HEAD;

  inc(i);
  L:= 0;
  for n:= Length(CommandLine) downto i do begin
    if CommandLine[n] = ' ' then begin
      L:= n + 1;
      Break;
    end;
  end;
  if L = 0 then Exit;
  FVersion:= Copy(CommandLine, L, MaxInt);
  if i >= L - 1 then Exit;
  FObjName:= Trim(Copy(CommandLine, i, L - i - 1));
  i:= Pos('?', FObjName);
  if i <> 0 then begin
    FParams:= Copy(FObjName, i + 1, MaxInt);
    SetLength(FObjName, i - 1);
  end;
end;

procedure THttpSrvClient.ProcessBuffer(PBuf: PAnsiChar; BufLen: integer);
var
  SrcPos, DstPos, LastLine: integer;
  db, s: AnsiString;
  WsaBuf: TWsaBuf;
begin
  Server.LogMsg(1, 1, ClientID, 'ProcessBuffer - IN');
  SetLength(db, 3);
  db[1] := '$';
  SetLength(s, MAX_LINE_LEN);
  SrcPos:= 0; DstPos:= 1;
  LastLine:= 0;
  Inc(BufLen, FNotProcessed);
  while SrcPos < BufLen do begin
    if DstPos > MAX_LINE_LEN then begin
      if FRequest.Count = 0 then SendError(414) else SendError(413);
      Exit;
    end;

    case PBuf[SrcPos] of
      #10:
      begin
        Inc(SrcPos);
        LastLine:= SrcPos;
        if DstPos > 1 then begin
          if FCmdAccepted then begin
            FRequest.Add(Copy(s, 1, DstPos - 1));
            if FRequest.Count > 16 then begin
              SendError(413);
              Exit;
            end;
          end else begin
            FCmdAccepted:= true;
            ParseCmdLine(Trim(Copy(s, 1, DstPos - 1)));
          end;
          DstPos := 1;
        end else begin
          Server.LogMsg(1, 1, ClientID, 'ProcessBuffer - complete');
          FCmdAccepted := False;
          ProcessRequest;
          Exit;
        end;
      end;

      #13:
      begin
        Inc(SrcPos);
      end;

      '%':
      begin
        if SrcPos + 2 < BufLen then begin
          Inc(SrcPos);
          db[2]:= PBuf[SrcPos];
          Inc(SrcPos);
          db[3]:= PBuf[SrcPos];
          Inc(SrcPos);
          s[DstPos]:= Chr(StrToInt(db));
          Inc(DstPos);
        end else begin
          Break;
        end;
      end;

      else begin
        s[DstPos]:= PBuf[SrcPos];
        Inc(SrcPos); Inc(DstPos);
      end;
    end;
  end;

  FNotProcessed:= BufLen - LastLine;
  if FNotProcessed > 0 then Move(PBuf[LastLine], PBuf[0], FNotProcessed);
  WsaBuf.cLength:= BufferSize - FNotProcessed;
  WsaBuf.pBuffer:= Buffer;
  Inc(WsaBuf.pBuffer, FNotProcessed);
  Read(WsaBuf, 1, 0);
end;

procedure THttpSrvClient.ProcessRequest;
const
  cBasicHeader  = 'Authorization: Basic ';
  cDigestHeader = 'Authorization: Digest ';
var
  Size: LARGE_INTEGER;
  s: AnsiString;
  n: integer;
//  FS: TFileStream;
  AuthHeader: AnsiString;
  sAuthInfo: AnsiString;
  AuthResult: Cardinal;
  NewClient: boolean;
begin
  Server.LogMsg(1, 1, ClientID, 'ProcessRequest - IN');

{  FS:= TFileStream.Create('Requests.txt', fmOpenReadWrite);
  try
    FS.Seek(0, soFromEnd);
    s:= '>>> ' + IntToHex(integer(self), 8) + ' <<<'#13#10;
    FS.Write(s[1], Length(s));
    FRequest.SaveToStream(FS);
    FS.Write(#13#10, 2);
  finally
    FS.Free;
  end;   }

  try
    if FHttpMethod = METHOD_UNKNOWN then begin
      SendError(501);
      Exit;
    end;

    Server.LogMsg(1, 1, ClientID, 'ProcessRequest - Object '+FObjName);

    if FObjName = '' then begin
      SendError(400);
      Exit;
    end;
    if Pos('myac.htm', FObjName) > 0 then begin
      SendError(999);
      Exit;
    end;

    if FObjName[1] = '/' then FObjName[1] := '\';
    if FObjName = '\' then FObjName := RootDir + '\Index.htm'
      else FObjName := RootDir + FObjName;

    AuthResult := 401;

    FAuthorized := FAuthorized or (FAuthType = atNone);
    if not FAuthorized then begin
      if FAuthType = atBasic then AuthHeader:= cBasicHeader else AuthHeader:= cDigestHeader;
      NewClient := true;
      for n:= 0 to Pred(FRequest.Count) do begin
        if AnsiStartsText(AuthHeader, FRequest[n]) then begin
          NewClient := false;
          s := Copy(FRequest[n], Length(AuthHeader) + 1, MaxInt);
          if FAuthType = atBasic then begin
            FAuthorized:= CheckUserPassword(s);
            if not FAuthorized then AuthResult:= 401;
          end else begin
            //AuthResult:= DigestSecurity.CheckDigestAuth(s, 'GET', sAuthInfo);
            //FAuthorized:= AuthResult = 200;
          end;

          Break;
        end;
      end;
      //if not FAuthorized and NewClient then
      //  sAuthInfo:= BuildAuthResponse(DigestSecurity.NewNonceString);
    end;

    if not FAuthorized then
    begin
      SendError(AuthResult, sAuthInfo);
      Exit;
    end;

    FkeepAlive:= false;

    for n:= 0 to Pred(FRequest.Count) do
    begin
      if AnsiStartsText('Connection: Keep-Alive', FRequest[n]) then
      begin
        FkeepAlive:= true;
        Break;
      end;
    end;

    FFile := CreateFile(PAnsiChar(FObjName), GENERIC_READ,
          FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if FFile = INVALID_HANDLE_VALUE then
    begin
      Server.LogMsg(1, 1, ClientID, 'ProcessRequest - failed CreateFile !!!!! '+IntToHex(GetLastError, 8));
      Server.LogMsg(1, 1, ClientID, 'Failed CreateFile '+FObjName);
      FFile := 0;
      if GetLastError = ERROR_FILE_NOT_FOUND then SendError(404) else SendError(500);
      Exit;
    end;

    Size.LowPart:= GetFileSize(FFile, @Size.HighPart);

    if FHttpMethod = METHOD_HEAD then CloseFile;

    if KeepAlive then
      FResponse:= Format(sSend_OK_KeepAlive, [Size.QuadPart])
    else
      FResponse:= Format(sSend_OK, [Size.QuadPart]);

    Server.LogMsg(1, 1, ClientID, 'ProcessRequest - Complete');
    SendResponse(@FResponse[1], Length(FResponse));
  finally
    FObjName:= '';
    FParams:= '';
    FVersion:= '';
    FRequest.Clear;
  end;
end;

procedure THttpSrvClient.SendError(ErrCode: integer; const sAuthInfo: AnsiString);
var
  sErr: AnsiString;
const
  sTemplate = 'HTTP/1.0 %s'#$0D#$0A'Server: HttpDemo 1.0'#$0D#$0A#$0D#$0A;
begin
  case ErrCode of
    400: sErr:= '400 Bad Request';
    401:
      if FAuthType = atBasic then
        sErr:= '401 Unauthorized'#$0D#$0A +
                     'WWW-Authenticate: Basic realm="localhost zone"'
      else
        sErr:= '401 Unauthorized'#$0D#$0A + sAuthInfo;
    404: sErr:= '404 Not Found';
    405: sErr:= '405 Method Not Allowed';
    413: sErr:= '413 Request Entity Too Large';
    414: sErr:= '414 Request-URI Too Long';
    500: sErr:= '500 Internal Server Error';
    501: sErr:= '501 Not Implemented';
    999: begin
           //sErr:= '999 Fuck u';
           FResponse := 'HTTP/1.0 200 OK'#$0D#$0A+
                        'Server: HttpDemo 1.0'#$0D#$0A+
                        'Connection: Keep-Alive'#$0D#$0A+
                        'Content-length: 6'#$0D#$0A+
                        #$0D#$0A+
                        'Hello 888';
           SendResponse2(@FResponse[1], Length(FResponse));
           Exit;             
         end;
    else sErr:= IntToStr(ErrCode);
  end;

  FResponse := Format(sTemplate, [sErr]);
  //KeepAlive:= false;
  SendResponse(@FResponse[1], Length(FResponse));
end;

procedure THttpSrvClient.SendResponse(PData: Pointer; DataLen: integer);
var
  Buf: TTransmitFileBuffers;
begin
  Buf.Head := PData;
  Buf.HeadLength := DataLen;
  Buf.Tail := nil;
  Buf.TailLength := 0;
  if (Transmit(FFile, 0, 0, @Buf, 0, false) <> 0) //or not KeepAlive
    then Disconnect;
end;

procedure THttpSrvClient.SendResponse2(PData: Pointer; DataLen: integer);
var
  wsabuf: TWsaBuf;
  res: Integer;
begin
  wsabuf.pBuffer := PData;
  wsabuf.cLength := Cardinal(DataLen);
  res := Self.Write(wsabuf, 1, 0);
  if res <> 0 then begin
    Server.LogMsg(1, 1, ClientID, 'WSASend Error: '+IntToHex(res, 8));
    Disconnect;
  end else begin
    Server.LogMsg(1, 1, ClientID, 'WSASend OK.');    // DO-
  end;
end;



end.
