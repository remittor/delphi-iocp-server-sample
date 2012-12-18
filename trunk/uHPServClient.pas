unit untClient;

(*******************************************************************************

Author: Sergey N. Naberegnyh

Created: August, 05, 2008
Updated: January, 23, 2009

// Cmd.exe -> netsh winsock reset    ???

*******************************************************************************)

interface

uses
  Windows, Messages, SysUtils, Classes,
  HPSockApi, HPScktSrvr, WinSock,
  JwaWinCrypt;

type
  THttpMethod = (METHOD_UNKNOWN, METHOD_GET, METHOD_HEAD);
  TAuthType   = (atNone, atBasic, atDigest);

  EDigestAuthInitError = Exception;

  TDigestSecurity = class;

  TNonceCountMask = array[0..7] of Cardinal;
  PNonceCountMask = ^TNonceCountMask;

  TDigestSession = class
  private
    FOwner: TDigestSecurity;
    FRefCount: integer;
    FCS: TRTLCriticalSection;
    FNonces: TStringList;
    FLastActivity: Cardinal;
    FID: LARGE_INTEGER;
    FUserName: AnsiString;
    FPassword: AnsiString;
    function NewNonce: AnsiString;
    function AddNonceString(const sNonce: AnsiString): boolean;
    procedure ClearNonces;
  protected
    function _AddRef: integer;
    function _Release: integer;
  public
    constructor Create(AOwner: TDigestSecurity;
      const User, Password, InitialNonce: AnsiString);
    destructor Destroy; override;

    function CheckNonce(const sNonce: AnsiString;
      nc: Cardinal; out Stale: boolean): boolean;

    procedure CheckLiveTime(CurrentTime, MaxLiveTime: Cardinal);  

    property RefCount: integer read FRefCount;
    property LastActivity: Cardinal read FLastActivity;
    property UserName: AnsiString read FUserName;
    property Password: AnsiString read FPassword;
  end;

  TStringList = Class(Classes.TStringList);

  TNonceBuffer = packed record
    Timestamp: TSystemTime;
    Hash: array[0..31] of Byte;
  end;

  TDigestSecurity = class
  private
    FCS: TRTLCriticalSection;
    FSessions, FUsers: TStringList;
    FCryptProv: HCRYPTPROV;
    FNonceCnt: integer;
    FNonceKey: array[0..32] of Byte;
    FEnumIndex: integer;
    function NewNonceString: AnsiString;
    function VerifyNonce(const sNonce: AnsiString;
      out Timeout: TDateTime): boolean;
    function FindSession(const sUser: AnsiString): TDigestSession;
    function FindUser(const UserName: AnsiString;
      out UserPasword: AnsiString): boolean;
  protected
    procedure Clear;
    procedure AddSession(Session: TDigestSession);
    procedure RemoveSession(Session: TDigestSession);
    function ParseDigestRequest(
                 const Request: AnsiString; const SL: TStrings): boolean;
  public
    constructor Create();
    destructor Destroy; override;

    function CheckDigestAuth(const AuthRequest: AnsiString;
      const sMethod: AnsiString; out AuthInfo: AnsiString): Cardinal;
    function CheckSessionsLiveTime(CurrentTime, MaxLiveTime: Cardinal): boolean;  
  end;

  THttpSrvClient = class(THPServerClient)
  private
    FClientID: integer;
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
    procedure CloseFile;
    property FileHandle: THandle read FFile;
  public
    constructor Create(); override;
    destructor Destroy; override;
    procedure Initialize; virtual;
    procedure Finalize; virtual;
    procedure DoWriteComplete(BytesTransfered: Cardinal;
      CompletionKey, Error: Integer); virtual;
    procedure ProcessBuffer(PBuf: PAnsiChar; BufLen: integer); virtual;
    property KeepAlive: boolean read FkeepAlive write FKeepAlive;
    property RequestHeader: TStringList read FRequest;
    property ClientID: Integer read FClientID;
  end;

var
  DigestSecurity: TDigestSecurity = nil;
  ClientIDs: Cardinal = 0;

implementation

uses
  untHttpMain, StrUtils, Math;

const
  cOpaque               = '07D0A5F7D91D43DBB30C0211F9FFDB3C';
  Current_Zone          = 'localhost zone';
  MICROSOFT_DIGEST_NAME = 'Microsoft Digest Security Protocol Provider';
  WDIGEST_SP_NAME       = 'WDigest';
  Session_Timeout = 5/(24 * 60);
  
function DecodeBase64(pSource: Pointer; SourceLen: DWORD;
  pDest: Pointer; var DestLen: DWORD): BOOL;
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
  if not Result then
  begin
    SetLastError(ERROR_INVALID_PARAMETER);
    Exit;
  end;

  Len:= (SourceLen div 4) * 3 + (SourceLen mod 4);
  if (pDest = nil) or (Len = 0) then
  begin
    DestLen:= Len;
    Exit;
  end;

  if Len > DestLen then
  begin
    Result:= false;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    Exit;
  end;

  i:= 0; d:= 0; dd:= 0;
  PD:= pDest; PS:= pSource;

  repeat

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then
    begin
      Inc(i);
      Continue;
    end;
    PD[d]:= Chr(Ord(b) shl 2);
    dd:= 1;
    Inc(i); Inc(d);
    if i >= SourceLen then Break;

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then
    begin
      Inc(i);
      Continue;
    end;
    PD[d - 1]:= Chr(Ord(PD[d - 1]) or ((b shr 4) and 3));
    PD[d]:= Chr((b shl 4) and $F0);
    Inc(i); Inc(d);
    if i >= SourceLen then Break;

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then
    begin
      Inc(i);
      Continue;
    end;
    PD[d - 1]:= Chr(Ord(PD[d - 1]) or ((b shr 2) and $0F));
    PD[d]:= Chr((b shl 6) and $FC);
    Inc(i); Inc(d);
    if i >= SourceLen then Break;

    k:= Ord(PS[i]);
    if k in [43..43 + High(BBase64)] then b:= BBase64[k - 43] else b:= $40;
    if b = $40 then
    begin
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
  Result:= '';
  if Source = '' then Exit;
  if not DecodeBase64(@Source[1], Length(Source), nil, L) then exit;
  Setlength(Result, L);
  L2:= L;
  if not DecodeBase64(@Source[1], Length(Source), @Result[1], L)
  then Result:= ''
  else if L2 <> L then SetLength(Result, L);
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
  for I := 0 to BufSize - 1 do
  begin
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
  Result:= Format(cDigestAuth, [sNonce, cOpaque]);
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
  if FFile <> 0 then
  begin
    CloseHandle(FFile);
    FFile:= 0;
  end;
end;

constructor THttpSrvClient.Create;
begin
  inherited;
  Inc(ClientIDs);
  FClientID:= ClientIDs;
  FRequest:= TStringList.Create;
  FRequest.Sorted:= true;
end;

destructor THttpSrvClient.Destroy;
begin
  Finalize;
  FRequest.Free;
  inherited;
end;

procedure THttpSrvClient.DoWriteComplete(BytesTransfered: Cardinal;
  CompletionKey, Error: Integer);
var
  WsaBuf: TWsaBuf;
begin
  CloseFile;
  FResponse:= '';
  if KeepAlive then 
  begin
    WsaBuf.cLength:= BufferSize;
    WsaBuf.pBuffer:= Buffer;
    if 0 <> Read(WsaBuf, 1, 0) then Disconnect;
  end else
    Disconnect;
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
{$IFDEF LOGGING_ON}
  Server.LogMessage(['ParseCmdLine - Line', PAnsiChar(CommandLine)], 0, 0, Cardinal(ClientID));
{$ENDIF}
  FHttpMethod:= METHOD_UNKNOWN;
  i:= Pos(' ', CommandLine);
  if i = 0 then exit;
  Command:= Copy(CommandLine, 1, i - 1);
  if Command = 'GET' then FHttpMethod:= METHOD_GET else
  if Command = 'HEAD' then FHttpMethod:= METHOD_HEAD;

  inc(i);
  L:= 0;
  for n:= Length(CommandLine) downto i do
  begin
    if CommandLine[n] = ' ' then
    begin
      L:= n + 1;
      Break;
    end;
  end;
  if L = 0 then Exit;
  FVersion:= Copy(CommandLine, L, MaxInt);
  if i >= L - 1 then Exit;
  FObjName:= Trim(Copy(CommandLine, i, L - i - 1));
  i:= Pos('?', FObjName);
  if i <> 0 then
  begin
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
{$IFDEF LOGGING_ON}
  Server.LogMessage(['ProcessBuffer - IN'], 0, 0, Cardinal(ClientID));
{$ENDIF}
  SetLength(db, 3);
  db[1]:= '$';
  SetLength(s, MAX_LINE_LEN);
  SrcPos:= 0; DstPos:= 1;
  LastLine:= 0;
  Inc(BufLen, FNotProcessed);
  while SrcPos < BufLen do
  begin
    if DstPos > MAX_LINE_LEN then
    begin
      if FRequest.Count = 0 then SendError(414)
      else SendError(413);
      Exit;
    end;

    case PBuf[SrcPos] of
      #10:
      begin
        Inc(SrcPos);
        LastLine:= SrcPos;
        if DstPos > 1 then
        begin
          if FCmdAccepted then
          begin
            FRequest.Add(Copy(s, 1, DstPos - 1));
            if FRequest.Count > 16 then
            begin
              SendError(413);
              Exit;
            end;
          end else
          begin
            FCmdAccepted:= true;
            ParseCmdLine(Trim(Copy(s, 1, DstPos - 1)));
          end;
          DstPos:= 1;
        end else
        begin
{$IFDEF LOGGING_ON}
          Server.LogMessage(['ProcessBuffer - complete'], 0, 0, Cardinal(ClientID));
{$ENDIF}
          FCmdAccepted:= false;
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
        if SrcPos + 2 < BufLen then
        begin
          Inc(SrcPos);
          db[2]:= PBuf[SrcPos];
          Inc(SrcPos);
          db[3]:= PBuf[SrcPos];
          Inc(SrcPos);
          s[DstPos]:= Chr(StrToInt(db));
          Inc(DstPos);
        end else
          Break;
      end;

      else begin
        s[DstPos]:= PBuf[SrcPos];
        Inc(SrcPos); Inc(DstPos);
      end;
    end;
  end;

  FNotProcessed:= BufLen - LastLine;
  if FNotProcessed > 0 then
    Move(PBuf[LastLine], PBuf[0], FNotProcessed);
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
{$IFDEF LOGGING_ON}
  Server.LogMessage(['ProcessRequest - IN'], 0, 0, Cardinal(ClientID));
{$ENDIF}

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
    if FHttpMethod = METHOD_UNKNOWN then
    begin
      SendError(501);
      Exit;
    end;

{$IFDEF LOGGING_ON}
    Server.LogMessage(['ProcessRequest - Object', PAnsiChar(FObjName)], 0, 0, Cardinal(ClientID));
{$ENDIF}

    if FObjName = '' then
    begin
      SendError(400);
      Exit;
    end;

    if FObjName[1] = '/' then FObjName[1]:= '\';
    if FObjName = '\' then FObjName:= RootDir + '\Index.htm'
    else FObjName:= RootDir + FObjName;

    AuthResult:= 401;

    FAuthorized:= FAuthorized or (FAuthType = atNone);
    if not FAuthorized then
    begin
      if FAuthType = atBasic then AuthHeader:= cBasicHeader
      else AuthHeader:= cDigestHeader;
      NewClient:= true;
      for n:= 0 to Pred(FRequest.Count) do
      begin
        if AnsiStartsText(AuthHeader, FRequest[n]) then
        begin
          NewClient:= false;
          s:= Copy(FRequest[n], Length(AuthHeader) + 1, MaxInt);
          if FAuthType = atBasic then
          begin
            FAuthorized:= CheckUserPassword(s);
            if not FAuthorized then AuthResult:= 401;
          end else
          begin
            AuthResult:= DigestSecurity.CheckDigestAuth(s, 'GET', sAuthInfo);
            FAuthorized:= AuthResult = 200;
          end;

          Break;
        end;
      end;
      if not FAuthorized and NewClient then
        sAuthInfo:= BuildAuthResponse(DigestSecurity.NewNonceString);
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

    FFile:= CreateFile(PAnsiChar(FObjName), GENERIC_READ,
          FILE_SHARE_READ, nil, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
    if FFile = INVALID_HANDLE_VALUE then
    begin
{$IFDEF LOGGING_ON}
      Server.LogMessage(['ProcessRequest - failed CreateFile !!!!!', PAnsiChar(IntToHex(GetLastError, 0))], 0, 0, Cardinal(ClientID));
      Server.LogMessage(['Failed CreateFile', PAnsiChar(FObjName)], 0, 0, Cardinal(ClientID));
{$ENDIF}
      FFile:= 0;
      if GetLastError = ERROR_FILE_NOT_FOUND then SendError(404)
      else SendError(500);
      Exit;
    end;


    Size.LowPart:= GetFileSize(FFile, @Size.HighPart);

    if FHttpMethod = METHOD_HEAD then CloseFile;

    if KeepAlive then
      FResponse:= Format(sSend_OK_KeepAlive, [Size.QuadPart])
    else
      FResponse:= Format(sSend_OK, [Size.QuadPart]);
{$IFDEF LOGGING_ON}
    Server.LogMessage(['ProcessRequest - Complete'], 0, 0, Cardinal(ClientID));
{$ENDIF}
    SendResponse(@FResponse[1], Length(FResponse));
  finally
    FObjName:= '';
    FParams:= '';
    FVersion:= '';
    FRequest.Clear;
  end;
end;

procedure THttpSrvClient.SendError(ErrCode: integer;
  const sAuthInfo: AnsiString);
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
    else sErr:= IntToStr(ErrCode);
  end;

  FResponse:= Format(sTemplate, [sErr]);
//  KeepAlive:= false;
  SendResponse(@FResponse[1], Length(FResponse));
end;

procedure THttpSrvClient.SendResponse(PData: Pointer; DataLen: integer);
var
  Buf: TTransmitFileBuffers;
begin
  Buf.Head:= PData;
  Buf.HeadLength:= DataLen;
  Buf.Tail:= nil;
  Buf.TailLength:= 0;
  if (0 <> Transmit(FFile, 0, 0, @Buf, 0, false)) //or not KeepAlive
  then Disconnect;
end;

{ TDigestSession }

function TDigestSession._AddRef: integer;
begin
  Result:= InterlockedIncrement(FRefCount);
end;

function TDigestSession._Release: integer;
begin
  Result:= InterlockedDecrement(FRefCount);
  if Result <= 0 then Destroy;
end;

{$Q-}
constructor TDigestSession.Create(AOwner: TDigestSecurity;
  const User: AnsiString; const Password: AnsiString;
  const InitialNonce: AnsiString);
begin
  InitializeCriticalSectionAndSpinCount(FCS, 400);
  FRefCount:= 1;
  FOwner:= AOwner;
  FUserName:= User;
  FPassword:= Password;
  FNonces:= TStringList.Create;
  FNonces.Sorted:= true;
  FNonces.Duplicates:= dupError;
  AddNonceString(InitialNonce);
  FLastActivity:= GetTickCount;
  CryptGenRandom(FOwner.FCryptProv, SizeOf(FID), @FID);
end;
{$Q+}

destructor TDigestSession.Destroy;
begin
  FOwner.RemoveSession(Self);
  ClearNonces;
  FNonces.Free;
  DeleteCriticalSection(FCS);
  inherited;
end;

function TDigestSession.AddNonceString(const sNonce: AnsiString): boolean;
var
//  n: integer;
  P: PNonceCountMask;
begin
  Result:= false;
  EnterCriticalSection(FCS);
  try
    GetMem(P, SizeOf(TNonceCountMask));
    FillChar(P^, SizeOf(P^), 0);
    try
      FNonces.AddObject(sNonce, TObject(P));
    except
      on E: Exception do
      begin
        FreeMem(P);
        if E is EStringListError then Exit;
        raise
      end;
    end;
    Result:= true;
  finally
    LeaveCriticalSection(FCS);
  end;
end;

function TDigestSession.CheckNonce(const sNonce: AnsiString;
  nc: Cardinal; out Stale: boolean): boolean;
var
  n: integer;  
  i: integer;
  m: Cardinal;
  P: PNonceCountMask;
  Timeout: TDateTime;
  NB: TNonceBuffer;
  ST: TSystemTime;
begin
  GetSystemTime(ST);
  EnterCriticalSection(FCS);
  try
    Result:= false;
    if nc < 1 then Exit;
    if not FNonces.Find(sNonce, n) then
    begin
      if nc <> 1 then Exit;
      if not FOwner.VerifyNonce(sNonce, Timeout) then Exit;
      if (Timeout < 0.0) or (Timeout > Session_Timeout) then
      begin
        Result:= true;
        Stale:= true;
        Exit;
      end;
      if not AddNonceString(sNonce) then Exit;
      FNonces.Find(sNonce, n);
    end;

    dec(nc);
    i:= nc div (8 * SizeOf(Cardinal));
    Stale:= i >= Length(P^);
    if Stale then Exit;
    m:= 1 shl (nc mod (8 * SizeOf(Cardinal)));

    P:= Pointer(FNonces.Objects[n]);
    Result:= P^[i] and m = 0;
    if not Result then Exit;
    P^[i]:= P^[i] or m;
  finally
    LeaveCriticalSection(FCS);
  end;

  HexToBin(PAnsiChar(sNonce), @NB, SizeOf(NB));
  NB.Timestamp.wMilliseconds:= 0;
  ST.wMilliseconds:= 0;
  Timeout:= SystemTimeToDateTime(ST) - SystemTimeToDateTime(NB.Timestamp);
  Stale:= (Timeout < 0.0) or (Timeout > Session_Timeout);
end;

procedure TDigestSession.ClearNonces;
var
  n: integer;
  P: PNonceCountMask;
begin
  EnterCriticalSection(FCS);
  try
    for n:= 0 to Pred(FNonces.Count) do
    begin
      P:= Pointer(FNonces.Objects[n]);
      if P <> nil then Dispose(P);
    end;
    FNonces.Clear;
  finally
    LeaveCriticalSection(FCS);
  end;
end;

function TDigestSession.NewNonce: AnsiString;
begin
  repeat
    Result:= FOwner.NewNonceString;
  until AddNonceString(Result);
end;

procedure TDigestSession.CheckLiveTime(CurrentTime, MaxLiveTime: Cardinal);
var
  D: LARGE_INTEGER;
  LA: Cardinal;
begin
  LA:= FLastActivity;
  D.LowPart:= CurrentTime;
  if CurrentTime < LA then D.HighPart:= 1 else D.HighPart:= 0;
  if D.QuadPart - LA > MaxLiveTime then _Release;
end;

{ TDigestSecurity }

procedure TDigestSecurity.AddSession(Session: TDigestSession);
begin
  EnterCriticalSection(FCS);
  try
    FSessions.AddObject(Session.UserName, Session);
  finally
    LeaveCriticalSection(FCS);
  end;
end;

function TDigestSecurity.CheckDigestAuth(const AuthRequest: AnsiString;
  const sMethod: AnsiString; out AuthInfo: AnsiString): Cardinal;
{Authorization: Digest username="user", realm="localhost zone",
 qop="auth", algorithm="MD5", uri="/", nonce="123", nc=00000001,
 cnonce="88dc73785da2ed87d736c60988e4ee97",
 opaque="456", response="6d260892abc94ed990f30c8f72d4e154"}
const
  cDigestAuth = 'WWW-Authenticate: Digest realm="localhost zone",' +
                ' qop="auth", %s' +
                ' nonce="%s", opaque="%s"';
  cDigestHiader = 'Authorization: Digest ';
  delim: AnsiChar = ':';
var
  s: string;
  sNonce, scNonce, Username, UserPsw, sURI, sRealm: AnsiString;
  A1, A2, sNonceCount, sQop: AnsiString;
  ucUser: AnsiString;
  Response: AnsiString;
  nc: Cardinal;
  Hash: HCRYPTHASH;
  HashVal: array[0..31] of Byte;
  HashSize, L: Cardinal;
  SL: TStringList;
  Session: TDigestSession;
  Stale: boolean;
  StaleStr: AnsiString;
  Timeout: TDateTime;
begin
  AuthInfo:= '';
  SL:= TStringList.Create;
  try
    try
      if not ParseDigestRequest(AuthRequest, SL) then
      begin
        Result:= 400;
        Exit;
      end;
    except
      Result:= 400;
      Exit;
    end;

    sNonce:= SL.Values['nonce'];
    if sNonce = '' then
    begin
      Result:= 400;
      Exit;
    end;

    Username:= SL.Values['username'];
    ucUser:= UpperCase(Username);

//    StaleStr:= '';
    Session:= FindSession(ucUser);
    if Session = nil then
    begin
      if VerifyNonce(sNonce, Timeout) and FindUser(ucUser, UserPsw) then
      begin
        if (Timeout >= 0.0) and (Timeout <= Session_Timeout) then
        begin
          Session:= TDigestSession.Create(Self, ucUser, UserPsw, sNonce);
          Session._AddRef;
          FSessions.AddObject(ucUser, Session);
        end else
          StaleStr:= 'stale="true", ';
      end;
    end;

    if Session = nil then
    begin
      Result:= 401;
      AuthInfo:= Format(cDigestAuth, [StaleStr, NewNonceString, cOpaque]);
      Exit;
    end;

    try

      sNonceCount:= SL.Values['nc'];
      if sNonceCount = '' then
      begin
        Result:= 400;
        Exit;
      end;

      if not TryStrToInt('$' + sNonceCount, integer(nc)) then nc:= 1;
      if (nc <= 1) and not AnsiSameText(SL.Values['opaque'], cOpaque) then
      begin
        Result:= 400;
        Exit;
      end;

      if Session.CheckNonce(sNonce, nc, Stale) then
      begin
        if Stale then
        begin
          Result:= 401;
          AuthInfo:= Format(cDigestAuth,
                       ['stale="true", ', Session.NewNonce, cOpaque]);
          Exit;
        end;
      end else
      begin
        Result:= 401;
        AuthInfo:= Format(cDigestAuth, ['', NewNonceString, cOpaque]);
        Exit;
      end;

      sRealm:= SL.Values['realm'];
      if not AnsiSameText(sRealm, Current_Zone) then
      begin
        Result:= 400;
        Exit;
      end;

      sQop:= SL.Values['qop'];
      if sQop = '' then
      begin
        Result:= 400;
        Exit;
      end;

      if not AnsiSameText(sQop, 'auth') then
      begin
        Result:= 401;
        sNonce:= Session.NewNonce;
        AuthInfo:= Format(cDigestAuth, ['', sNonce, cOpaque]);
        Exit;
      end;

      s:= SL.Values['algorithm'];
      if (s <> '') and not AnsiSameText(s, 'MD5') then
      begin
        Result:= 401;
        sNonce:= Session.NewNonce;
        AuthInfo:= Format(cDigestAuth, ['', sNonce, cOpaque]);
        Exit;
      end;

      sURI:= SL.Values['uri'];
      if sURI = '' then
      begin
        Result:= 400;
        Exit;
      end;

      scNonce:= SL.Values['cnonce'];
      if scNonce = '' then
      begin
        Result:= 400;
        Exit;
      end;

      UserPsw:= Session.Password;
      if not CryptCreateHash(FCryptProv, CALG_MD5, 0, 0, Hash) then
      begin
        Result:= 500;
        Exit;
      end;

      CryptHashData(Hash, @Username[1], Length(Username), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @sRealm[1], Length(sRealm), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @UserPsw[1], Length(UserPsw), 0);
      L:= SizeOf(HashSize);
      CryptGetHashParam(Hash, HP_HASHSIZE, @HashSize, L, 0);
      CryptGetHashParam(Hash, HP_HASHVAL, @HashVal, HashSize, 0);
      CryptDestroyHash(Hash);
      A1:= BinToHex(@HashVal, HashSize);

      if not CryptCreateHash(FCryptProv, CALG_MD5, 0, 0, Hash) then
      begin
        Result:= 500;
        Exit;
      end;
      CryptHashData(Hash, @sMethod[1], Length(sMethod), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @sURI[1], Length(sURI), 0);
      L:= SizeOf(HashSize);
      CryptGetHashParam(Hash, HP_HASHSIZE, @HashSize, L, 0);
      CryptGetHashParam(Hash, HP_HASHVAL, @HashVal, HashSize, 0);
      CryptDestroyHash(Hash);
      A2:= BinToHex(@HashVal, HashSize);

      if not CryptCreateHash(FCryptProv, CALG_MD5, 0, 0, Hash) then
      begin
        Result:= 500;
        Exit;
      end;
      CryptHashData(Hash, @A1[1], Length(A1), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @sNonce[1], Length(sNonce), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @sNonceCount[1], Length(sNonceCount), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @scNonce[1], Length(scNonce), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @sQop[1], Length(sQop), 0);
      CryptHashData(Hash, @Delim, 1, 0);
      CryptHashData(Hash, @A2[1], Length(A2), 0);
      L:= SizeOf(HashSize);
      CryptGetHashParam(Hash, HP_HASHSIZE, @HashSize, L, 0);
      CryptGetHashParam(Hash, HP_HASHVAL, @HashVal, HashSize, 0);
      CryptDestroyHash(Hash);
      Response:= BinToHex(@HashVal, HashSize);

      if SL.Values['response'] = Response then
      begin
        Result:= 200;
      end else
      begin
        Result:= 401;
        sNonce:= Session.NewNonce;
        AuthInfo:= Format(cDigestAuth, ['', sNonce, cOpaque]);
      end;

    finally
      Session._Release;
    end;

  finally
    SL.Free;
  end;
end;

function TDigestSecurity.VerifyNonce(const sNonce: AnsiString;
  out Timeout: TDateTime): boolean;
var
  NB, NBTest: TNonceBuffer;
  SizeLen, HashLen: Cardinal;
  NonceLen: integer;
  H: HCRYPTHASH;
begin
  GetSystemTime(NBTest.Timestamp);
  NonceLen:= Length(sNonce);
  Result:= NonceLen <= SizeOf(NB) * 2;
  if not Result then Exit;
  Result:= (NonceLen div 2) = HexToBin(PAnsiChar(sNonce), @NB, SizeOf(NB));
  if not Result then Exit;
  Result:= false;
  if not CryptCreateHash(FCryptProv, CALG_MD5, 0, 0, H) then exit;
  try
    CryptHashData(H, @NB.Timestamp, SizeOf(NB.Timestamp), 0);
    CryptHashData(H, @FNonceKey, SizeOf(FNonceKey), 0);
    SizeLen:= SizeOf(HashLen);
    if not CryptGetHashParam(H, HP_HASHSIZE, @HashLen, SizeLen, 0) then Exit;
    if HashLen > SizeOf(NBTest.Hash) then Exit;
    if not CryptGetHashParam(H, HP_HASHVAL, @NBTest.Hash, HashLen, 0) then Exit;
    Result:= CompareMem(@NB.Hash, @NBTest.Hash, HashLen);
    if not Result then Exit;
  finally
    CryptDestroyHash(H);
  end;
  NB.Timestamp.wMilliseconds:= 0;
  NBTest.Timestamp.wMilliseconds:= 0;
  Timeout:=
    SystemTimeToDateTime(NBTest.Timestamp) - SystemTimeToDateTime(NB.Timestamp);
end;

procedure TDigestSecurity.Clear;
var
  n: integer;
begin
  EnterCriticalSection(FCS);
  try
    for n:= Pred(FSessions.Count) downto 0 do
      TDigestSession(FSessions.Objects[n])._Release;
    FSessions.Clear;  
  finally
    LeaveCriticalSection(FCS);
  end;
end;

constructor TDigestSecurity.Create;
begin
  InitializeCriticalSectionAndSpinCount(FCS, 4000);
  if not CryptAcquireContext(FCryptProv, nil, nil,
                            PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
    raise EDigestAuthinitError.Create(SysErrorMessage(GetLastError));
  CryptGenRandom(FCryptProv, SizeOf(FNonceKey), @FNonceKey);

  FSessions:= TStringList.Create;
  FSessions.Capacity:= 1024;
  FSessions.Sorted:= false;
  FSessions.Duplicates:= dupError;

  FUsers:= TStringList.Create;
  if FileExists('Users.txt') then FUsers.LoadFromFile('Users.txt');
end;

destructor TDigestSecurity.Destroy;
begin
  Clear;
  FSessions.Free;
  FUsers.Free;
  if FCryptProv <> 0 then CryptReleaseContext(FCryptProv, 0);
  DeleteCriticalSection(FCS);
  inherited;
end;

function TDigestSecurity.FindSession(const sUser: AnsiString): TDigestSession;
var
  n: integer;
begin
  EnterCriticalSection(FCS);
  try
    if FSessions.Find(UpperCase(sUser), n) then
    begin
      Result:= TDigestSession(FSessions.Objects[n]);
      Result.FLastActivity:= GetTickCount;
      Result._AddRef;
    end else
      Result:= nil;  
  finally
    LeaveCriticalSection(FCS);
  end;
end;

function TDigestSecurity.NewNonceString: AnsiString;
var
  NB: TNonceBuffer;
  H: HCRYPTHASH;
  SizeLen, HashLen: Cardinal;
begin
  GetSystemTime(NB.Timestamp);
  NB.Timestamp.wMilliseconds:= Word(InterlockedIncrement(FNonceCnt));
  if not CryptCreateHash(FCryptProv, CALG_MD5, 0, 0, H) then exit;
  try
    CryptHashData(H, @NB.Timestamp, SizeOf(NB.Timestamp), 0);
    CryptHashData(H, @FNonceKey, SizeOf(FNonceKey), 0);
    SizeLen:= SizeOf(HashLen);
    if not CryptGetHashParam(H, HP_HASHSIZE, @HashLen, SizeLen, 0) then Exit;
    if HashLen > SizeOf(NB.Hash) then Exit;
    if not CryptGetHashParam(H, HP_HASHVAL, @NB.Hash, HashLen, 0) then Exit;
    Result:= BinToHex(@NB, SizeOf(NB.Timestamp) + HashLen);
  finally
    CryptDestroyHash(H);
  end;
end;

function TDigestSecurity.ParseDigestRequest(const Request: AnsiString;
  const SL: TStrings): boolean;
var
  P, P0: PChar;
  Name, Value: AnsiString;
begin
  Result:= Request <> '';
  SL.Clear;
  if not Result then Exit;
  P:= @Request[1];

  while P^ <> #0 do
  begin
    if P^ = ' ' then
    begin
      P:= CharNext(P);
      Continue;
    end;
    Result:= false;
    P0:= P;
    while not (P^ in [#0..' ', '=']) do P:= CharNext(P);
    SetString(Name, P0, P - P0);
    if Name = '' then Exit;
    if P^ <> '=' then Exit;
    P:= CharNext(P);
    while P^ = ' ' do P:= CharNext(P);
    if P^ = '"' then Value:= AnsiExtractQuotedStr(P, '"') else
    begin
      while P^ = ' ' do P:= CharNext(P);
      if P^ = #0 then Exit;
      P0:= P;
      while not (P^ in [#0, ' ', ',']) do P:= CharNext(P);
      SetString(Value, P0, P - P0);
    end;

    SL.Values[Name]:= Value;
    Result:= true;
    while not (P^ in [#0, ',']) do P:= CharNext(P);
    if P^ = ',' then P:= CharNext(P);
  end;
end;

function TDigestSecurity.FindUser(const UserName: AnsiString;
  out UserPasword: AnsiString): boolean;
begin
  UserPasword:= FUsers.Values[UserName];
  Result:= UserPasword <> '';
end;

function TDigestSecurity.CheckSessionsLiveTime(
  CurrentTime, MaxLiveTime: Cardinal): boolean;
begin
  EnterCriticalSection(FCS);
  try
    if (FEnumIndex <= 0) or (FEnumIndex > FSessions.Count) then
      FEnumIndex:= FSessions.Count;
    Dec(FEnumIndex);
    if FEnumIndex >= 0 then
      TDigestSession(FSessions.Objects[FEnumIndex]).
                      CheckLiveTime(CurrentTime, MaxLiveTime);
    Result:= FEnumIndex > 0;                  
  finally
    LeaveCriticalSection(FCS);
  end;
end;

procedure TDigestSecurity.RemoveSession(Session: TDigestSession);
var
  n: integer;
begin
  EnterCriticalSection(FCS);
  try
    if FSessions.Find(Session.UserName, n) then
      FSessions.Delete(n);
  finally
    LeaveCriticalSection(FCS);
  end;
end;

end.
