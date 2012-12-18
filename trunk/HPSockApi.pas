unit HPSockApi;

(*******************************************************************************

Author: Sergey N. Naberegnyh

Version 1.3.0.0
Created: December, 03, 2008
Updated: January, 23, 2009

&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
January, 23, 2009
- Dynamic loading IPv6 functions for Wnn2k compatibility
*******************************************************************************)

interface

uses
  Windows, SysUtils, WinSock;

const
// GetAddrInfo helper flags

  AI_PASSIVE            = $01; // Socket address will be used in bind() call
  AI_CANONNAME          = $02; // Return canonical name in first ai_canonname
  AI_NUMERICHOST        = $04; // Nodename must be a numeric address string

  AF_INET6              = 23;
  PF_INET6              = AF_INET6;
  
// TransmitFile functions flags

  TF_DISCONNECT         = $01;
  TF_REUSE_SOCKET       = $02;
  TF_WRITE_BEHIND       = $04; // TransmitFile only (MSDN)
  TF_USE_DEFAULT_WORKER = $00;
  TF_USE_SYSTEM_THREAD  = $10;
  TF_USE_KERNEL_APC     = $20;

// QueueUserWorkItem flags

  WT_EXECUTEDEFAULT                 = $00000000;
  WT_EXECUTEINIOTHREAD              = $00000001;
  WT_EXECUTEINPERSISTENTTHREAD      = $00000080;
  WT_EXECUTELONGFUNCTION            = $00000010;

  WSA_IO_PENDING = ERROR_IO_PENDING;
  SOMAXCONN2     = $7fffffff;

  WSAID_DISCONNECTEX: TGUID =
    (D1: $7fda2e11; D2: $8630; D3: $436f;
     D4: ($a0, $31, $f5, $36, $a6, $ee, $c1, $57));
  WSAID_TRANSMITFILE: TGUID =
    (D1: $b5367df0; D2: $cbac; D3: $11cf;
     D4: ($95, $ca, $00, $80, $5f, $48, $a1, $92));
  WSAID_ACCEPTEX: TGUID =
    (D1: $b5367df1; D2: $cbac; D3: $11cf;
     D4: ($95, $ca, $00, $80, $5f, $48, $a1, $92));
  WSAID_GETACCEPTEXSOCKADDRS: TGUID =
    (D1: $b5367df2; D2: $cbac; D3: $11cf;
     D4: ($95, $ca, $00, $80, $5f, $48, $a1, $92));

  SIO_GET_EXTENSION_FUNCTION_POINTER = $C8000006;

  CS_Alloc_Event   = Cardinal(1 shl ((8 * SizeOf(Cardinal)) - 1));

type
  PSListEntry = pointer;

  PSListHeader = ^TSListHeader;
  TSListHeader = record
    Dummy: Int64;
  end;

  TSListFunc = record
    InitHeader: procedure (SListHeader: PSListHeader); stdcall;
    PushSListEntry: function (SListHeader: PSListHeader;
                 SListEntry: PSListEntry): PSListEntry; stdcall;
    PopSListEntry: function (SListHeader: PSListHeader): PSListEntry; stdcall;
    FlushSList: function (SListHeader: PSListHeader): PSListEntry; stdcall;
    QueryDepth: function (SListHeader: PSListHeader): WORD; stdcall;
    Presents: boolean;
  end;

type
  ESockAddrError = class(Exception)
    ErrCode: integer;
    constructor Create(Code: integer); overload;
  end;

  PAddrInfo = ^addrinfo;
  addrinfo = packed record
    ai_flags: integer;
    ai_family: integer;
    ai_socktype: integer;
    ai_protocol: integer;
    ai_addrlen: Cardinal;
    ai_canonname: PAnsiChar;
    ai_addr: PSockAddrIn;
    ai_next: PAddrInfo;
  end;
  TAddrInfo = addrinfo;

  PAddrInfoW = ^addrinfow;
  addrinfow = packed record
    ai_flags: integer;
    ai_family: integer;
    ai_socktype: integer;
    ai_protocol: integer;
    ai_addrlen: Cardinal;
    ai_canonname: PWideChar;
    ai_addr: PSockAddrIn;
    ai_next: PAddrInfo;
  end;
  TAddrInfoW = addrinfow;

  PWsaBuf = ^TWsaBuf;
  TWsaBuf = packed record
    cLength: ULONG;
    pBuffer: PByte;
  end;

  TDisconnectEx         = function(Socket: TSocket; pOvp: POverlapped;
                            Flags: DWORD; Reserved: DWORD): BOOL; stdcall;
  TAcceptEx             = function(ListenSocket, AcceptSocket: TSocket;
                            pOutBuff: Pointer; ReceiveDataLen, LocalAddrLen,
                            RemoteAddrLen: DWORD; var BytesReceived: DWORD;
                            pOverlapped: POverlapped): BOOL; stdcall;
  TGetAcceptExSockaddrs = procedure(lpOutputBuffer: Pointer;
                            dwReceiveDataLength, dwLocalAddressLength,
                            dwRemoteAddressLength: DWORD;
                            var LocalSockaddr: PSockAddrin;
                            var LocalSockaddrLength: integer;
                            var RemoteSockaddr: PSockAddrIn;
                            var RemoteSockaddrLength: Integer); stdcall;
  TTransmitFile         = function(s: TSocket; hFile: THandle;
                            NumberOfBytesToWrite: DWORD;
                            NumberOfBytesPerSend: DWORD;
                            pOvp: POverlapped;
                            pTransmitBuffers: PTransmitFileBuffers;
                            dwFlags: DWORD): BOOL; stdcall;

  TGetAddrInfo          = function (nodename, servname: PAnsiChar;
                            pHints: PAddrInfo;
                            out res: PAddrInfo): integer; stdcall;

  TGetAddrInfoW         = function (nodename, servname: PWideChar;
                            pHints: PAddrInfoW;
                            out res: PAddrInfoW): integer; stdcall;

  TFreeAddrInfo         = procedure (pai: PAddrInfo); stdcall;

  TFreeAddrInfoW        = procedure (pai: PAddrInfoW); stdcall;

  TGetThreadIOPendingFlag = function(hThread: THandle;
                                 out IOIsPending: Longbool): BOOL; stdcall;
  TNtQueryInformationThread = function(hThread: THandle;
                      ThreadInformationClass: DWORD; out ThreadInformation;
                      ThreadInformationLength : ULONG;
                      ReturnLength : PULONG): DWORD; stdcall;

const
  WS2_32_LIB = 'ws2_32.dll';

{function getaddrinfo(nodename, servname: PAnsiChar;
  pHints: PAddrInfo; out res: PAddrInfo): integer; stdcall external WS2_32_LIB;
function GetAddrInfoW(nodename, servname: PWideChar;
  pHints: PAddrInfoW; out res: PAddrInfoW): integer; stdcall external WS2_32_LIB;
procedure freeaddrinfo(pai: PAddrInfo); stdcall external WS2_32_LIB;
procedure FreeAddrInfoW(pai: PAddrInfoW); stdcall external WS2_32_LIB;  }

function WSARecv(s: TSocket; var Buffers: TWsaBuf; dwBufCount: DWORD;
              var BytesTransfered: DWORD; var Flags: DWORD;
              pOvp: POverlapped; pCompletionRoutine: pointer): Integer;
              stdcall; external  WS2_32_LIB;

function WSASend(s: TSocket; var Buffers : TWsaBuf; dwBufCount: DWORD;
              var BytesTransfered: DWORD; dwFlags: DWORD;
              pOvp: POverlapped; pCompletionRoutine: Pointer): Integer;
              stdcall; external  WS2_32_LIB;

function WSAIoctl(socket: TSocket; IoControlCode: DWORD; pInBuffer: Pointer;
              cbInBuffer: DWORD; pOutBuffer: Pointer; cbOutBuffer: DWORD;
              pBytesReturned: PDWORD; pOvp: POverlapped;
              pCompletionRoutine: pointer): integer;
              stdcall; external  WS2_32_LIB;

function BindIoCompletionCallback(hFile: THandle; CallbackFunc: Pointer;
  Flags: ULONG): BOOL; stdcall; external kernel32;

function QueueUserWorkItem(CallbackFunc: Pointer; pContext: Pointer;
  Flags: ULONG): BOOL; stdcall; external kernel32;

function GetExtensionFunc(Socket: TSocket; const FID: TGUID): pointer;
procedure InitSListFunc(var SListFunc: TSListFunc);

procedure ResolveAddressAndPort(const HostNameOrAddr,
  ServiceOrPort, Proto: string; out Addr: TSockAddrIn);

function ResolveAddressAndPortV6(ServerSide: boolean; const HostNameOrAddr,
  ServiceOrPort: AnsiString; Family, SockType: integer): PAddrInfo; overload;
function ResolveAddressAndPortV6(ServerSide: boolean; const HostNameOrAddr,
  ServiceOrPort: WideString; Family, SockType: integer): PAddrInfoW; overload;

{### Added June, 30, 2009}
function ThreadIsIoPending(hThread: THandle): bool;
{### /Added}

var
  F_GetAddrInfo:               TGetAddrInfo               = nil;
  F_GetAddrInfoW:              TGetAddrInfoW              = nil;
  F_FreeAddrInfo:              TFreeAddrInfo              = nil;
  F_FreeAddrInfoW:             TFreeAddrInfoW             = nil;
{### Added June, 30, 2009}
  F_GetThreadIOPendingFlag:    TGetThreadIOPendingFlag    = nil;
  F_NtQueryInformationThread:  TNtQueryInformationThread  = nil;
{### /Added}

const
  _IPv6Supported: boolean = false;

implementation

var
  HWs2_32Lib: HMODULE = 0;
  HNtDll    : HMODULE = 0;
  
{ ESockAddrError }

constructor ESockAddrError.Create(Code: integer);
begin
  ErrCode:= Code;
  Create(SysErrorMessage(ErrCode));
end;

{### Added June, 30, 2009}
function InternalGetThreadIOPending(hThread: THandle;
  out IOIsPending: Longbool): BOOL; stdcall;
var
  Info, RetLen: ULONG;
begin
  Result:= nil = @F_NtQueryInformationThread;
  if Result then exit;
  Result:= 0 = F_NtQueryInformationThread(hThread, 16, Info, SizeOf(Info), @RetLen);
  IOIsPending:= (not Result) or (Info <> 0);
end;

function ThreadIsIoPending(hThread: THandle): bool;
begin
  if not F_GetThreadIOPendingFlag(hThread, Result) then Result:= true;
end;
{### /Added}

function GetExtensionFunc(Socket: TSocket; const FID: TGUID): pointer;
var
  ret: cardinal;
begin
  Result:= nil;
  if 0 <> WSAIoctl(Socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
    @FID, sizeof(TGUID), @Result, SizeOf(Result), @ret, nil, nil)
  then Result:= nil;
end;

procedure ResolveAddressAndPort(const HostNameOrAddr,
  ServiceOrPort, Proto: string; out Addr: TSockAddrIn);
var
  n, c: integer;
  pSE: PServEnt;
  p: PAnsiChar;
  pHost: PHostEnt;
begin
  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family:= AF_INET;

  if '' = HostNameOrAddr then
    Addr.sin_addr.S_addr:= htonl(INADDR_ANY)
  else
    Addr.sin_addr.S_addr:= inet_addr(PAnsiChar(HostNameOrAddr));
  if INADDR_NONE = Addr.sin_addr.S_addr then
  begin
    pHost:= gethostbyname(PAnsiChar(HostNameOrAddr));
    if nil <> pHost then
    begin
      p:= pHost.h_addr_list^;
      with Addr.sin_addr.S_un_b do
      begin
        s_b1:= p[0];
        s_b2:= p[1];
        s_b3:= p[2];
        s_b4:= p[3];
      end;
    end else
      raise ESockAddrError.Create(WSAEADDRNOTAVAIL);
  end;

  Val(ServiceOrPort, n, c);
  if 0 <> c then
  begin
    pSE:= getservbyname(PAnsiChar(ServiceOrPort), PAnsiChar(Proto));
    if nil = pSE then
      raise ESockAddrError.Create(WSAGetLastError);
    Addr.sin_port:= u_short(pSE.s_port);
  end else
    Addr.sin_port:= htons(u_short(n));
end;

function ResolveAddressAndPortV6(ServerSide: boolean; const HostNameOrAddr,
  ServiceOrPort: AnsiString; Family, SockType: integer): PAddrInfo; overload;
var
  Hint: TAddrInfo;
  Rslt: integer;
  P: PAnsiChar;
begin
  if not _IPv6Supported then
  begin
    Result:= nil;
    Exit;
  end;

  FillChar(Hint, SizeOf(Hint), 0);
  Hint.ai_family:= Family;
  Hint.ai_socktype:= SockType;
  if ServerSide then Hint.ai_flags:= AI_NUMERICHOST or AI_PASSIVE;
  if '' = HostNameOrAddr then P:= nil
  else P:= @HostNameOrAddr[1];

  Rslt:= F_GetAddrInfo(P, PAnsiChar(ServiceOrPort), @Hint, Result);

  if 0 <> Rslt then raise ESockAddrError.Create(Rslt);
end;

function ResolveAddressAndPortV6(ServerSide: boolean; const HostNameOrAddr,
  ServiceOrPort: WideString; Family, SockType: integer): PAddrInfoW; overload;
var
  Hint: TAddrInfoW;
  Rslt: integer;
  P: PWideChar;
begin
  if not _IPv6Supported then
  begin
    Result:= nil;
    Exit;
  end;

  FillChar(Hint, SizeOf(Hint), 0);
  Hint.ai_family:= Family;
  Hint.ai_socktype:= SockType;
  if ServerSide then Hint.ai_flags:= AI_NUMERICHOST or AI_PASSIVE;
  if '' = HostNameOrAddr then P:= nil
  else P:= @HostNameOrAddr[1];

  Rslt:= F_GetAddrInfoW(P, PWideChar(ServiceOrPort), @Hint, Result);

  if 0 <> Rslt then raise ESockAddrError.Create(Rslt);
end;

procedure InitSListFunc(var SListFunc: TSListFunc);
var
  H: HMODULE;
begin
  SListFunc.Presents:= false;
  H:= GetModuleHandle('kernel32.dll');

  with SListFunc do
  begin
    @InitHeader:= GetProcAddress(H, 'InitializeSListHead');
    if not Assigned(InitHeader) then Exit;
    @PushSListEntry:= GetProcAddress(H, 'InterlockedPushEntrySList');
    if not Assigned(PushSListEntry) then Exit;
    @PopSListEntry:= GetProcAddress(H, 'InterlockedPopEntrySList');
    if not Assigned(PopSListEntry) then Exit;
    @FlushSList:= GetProcAddress(H, 'InterlockedFlushSList');
    if not Assigned(FlushSList) then Exit;
    @QueryDepth:= GetProcAddress(H, 'QueryDepthSList');
    Presents:= Assigned(QueryDepth);
  end;
end;

procedure InitUnit();
begin
  HWs2_32Lib:= LoadLibrary(WS2_32_LIB);
  if 0 = HWs2_32Lib then Exit;
  @F_GetAddrInfo:= GetProcAddress(HWs2_32Lib, 'getaddrinfo');
  @F_GetAddrInfoW:= GetProcAddress(HWs2_32Lib, 'GetAddrInfoW');
  @F_FreeAddrInfo:= GetProcAddress(HWs2_32Lib, 'freeaddrinfo');
  @F_FreeAddrInfoW:= GetProcAddress(HWs2_32Lib, 'FreeAddrInfoW');
  _IPv6Supported:= (nil <> @F_GetAddrInfo) and (nil <> @F_GetAddrInfoW)
      and (nil <> @F_FreeAddrInfo) and (nil <> @F_FreeAddrInfoW);

{### Added June, 30, 2009}
  @F_GetThreadIOPendingFlag:=
    GetProcAddress(GetModuleHandle(kernel32), 'GetThreadIOPendingFlag');
  if nil = @F_GetThreadIOPendingFlag then
    @F_GetThreadIOPendingFlag:= @InternalGetThreadIOPending;
  HNtDll:= LoadLibrary('ntdll.dll');
  if 0 <> HNtDll then
    @F_NtQueryInformationThread:= GetProcAddress(HNtDll, 'NtQueryInformationThread');
{### /Added}

end;

procedure FinalizeUnit();
begin
  if 0 <> HWs2_32Lib then FreeLibrary(HWs2_32Lib);
  if 0 <> HNtDll then FreeLibrary(HNtDll);
end;

initialization
  InitUnit();

finalization
  FinalizeUnit(); 

end.
