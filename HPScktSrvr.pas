unit HPScktSrvr;

{!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

                              W_A_R_N_I_N_G !

-- Component THPServerSocketSPL provided ONLY AS EXAMPLE of using
   "System Thread Pool" and NOT RECOMMENDED for practical use.
   Use component THPServerSocket instead this.

-- Directive "USE_SLIST" enabled using SList functions. These functions
   available  only on Windows XP and higher versions. Do not define this
   directive if You need to support Windows 2000.

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!}

(*******************************************************************************

Author: Sergey N. Naberegnyh

Version 1.4.0.7
Created: August, 05, 2008
Updated: July, 26, 2009

&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
November, 22, 2008:
 Not raised TCustomHPServerSocket.OnCreateAcceptor - Fixed
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
December, 03, 2008
- Included IPv6 support
- Restructuring unit
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
December, 04, 2008
- Support IPv6
- Adedded property "MinimumAcceptors"
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
January, 23, 2009
- Dynamic loading IPv6 functions for Win2k compatibility
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
January, 31, 2009
- AcceptEx failed if function TransmitFile
    with DisconnectClient = TRUE return error
  Fixed:
    1) Added "closesocket" in
       THPServerWorkThread.Execute: HPSO_TRANSMIT_DISCONNECT block.
    2) In TAcceptThread.Execute "Break" operator replaced to "Continue"
       
- Fixed: Memory leaks if failed THPServerClient.Read, Write and Transmit
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
June, 30, 2009
- DecreaseWorkThreads routine changed
- OnAcceptorStart and OnAcceptorEnd events are added.

- TCustomHPServerClient.WaitConnectionData are added.
  By default is "TRUE"
    If this property is "FALSE" or "ConnBufSize" parameter in
  "OnClientBeforeAccept" event handler equal to null, "OnClientConnect" event
  raised as soon as connection arrives, without waiting for any data.
  Otherwise "OnClientConnect" event raised only after data is received.
&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&
July, 26, 2009
- Fixed bug: client not removed from connections list
*******************************************************************************)

{$WARN SYMBOL_PLATFORM OFF}

{$DEFINE MINWINXP}

{$IFDEF MINWINXP}
{$DEFINE USE_SLIST}
{$ENDIF}

interface

uses
  Windows, Classes, SysUtils, WinSock,
  HPSockApi, CompletionPort;

const
  MAX_WSA_BUFFERS = 32;

  DefClientsCapacity      = 1024;
  DefStuctStackCapacity   = 4096;
  DefAcceptorsCount       = 10;
  DefMinAcceptors         = 5;
  DefThreadsPerProcessor  = 4;

  Addr_Buf_Len = SizeOf(TSockAddrIn) + 16;

resourcestring
  sAcceptExNotFound = 'Function "AcceptEx" not found in current system.';
  sGetAcceptExSockaddrsNotFound = 'Function "GetAcceptExSockaddrs" not found in current system.';
  sClassInvalid = 'Invalid class of client';

type
  TCustomHPServerClient = class;
  THPServerClientSPL = class;
  THPServerClient = class;
  TCustomHPServerSocket = class;
  THPServerSocketSPL = class;
  TClientList = class;

  THPSockOpCode = (HPSO_ACCEPT, HPSO_READ, HPSO_WRITE,
    HPSO_TRANSMITFILE, HPSO_TRANSMIT_DISCONNECT,
    HPSO_DISCONNECT, HPSO_USERASYNCCALL);
  
  PHPSockIOStructSPL = ^THPSockIOStructSPL;
  THPSockIOStructSPL = record
    Ovp: TOverlapped;
    CompletionKey: integer;
    Error: integer;
    OpCode: THPSockOpCode;
    BuffersCount: integer;
    Buffers: array [0..MAX_WSA_BUFFERS - 1] of TWsaBuf;
    Client: THPServerClientSPL;
  end;

  PHPSockIOStruct = ^THPSockIOStruct;
  THPSockIOStruct = record
    Ovp: TOverlapped;
    CompletionKey: integer;
    OpCode: THPSockOpCode;
    Client: THPServerClient;
  end;

  TUserKeyRange = 16..MAXDWORD - 1;

  EHPServerException = class(Exception);

  THPServerThread = class(TThread)
  private
    FEvent: THandle;
    procedure ClearClientsStack(const Stack: TClientList);
  public
    constructor Create(CreateSyspended: boolean);
    destructor Destroy; override;
    procedure Notify();
    procedure Terminate();
    function WaitForTimeout(TimeOut: cardinal): boolean;
  end;

  TCustomHPServerClient = class
  private
    FNext, FPrev: TCustomHPServerClient;
    FList: TClientList;
    FServer: TCustomHPServerSocket;
    FSocket: TSocket;
    FRefCount: integer;
    FConnected: LongBool;
    FPStruct: Pointer;
    FLocalAddr,
    FRemoteAddr: TSockAddrIn;
    FAddrOffset: integer;
    FpConnectBuf: PByte;
    FConnBufSize: integer;
    FWaitConnectionData: boolean;
    function ExchangeStruct(P: Pointer): Pointer;
    function ExtractSocket(): TSocket;
    function GetLocalAddress: string;
    function GetLocalHost: string;
    function GetLocalPort: Integer;
    function GetRemoteAddr: TSockAddrIn;
    function GetRemoteAddress: string;
    function GetRemoteHost: string;
    function GetRemotePort: Integer;
    procedure ExtractAddresses();
    function GetConnectionTime: Cardinal;
    procedure ReallocConnBuf(NewSize: integer);
    function GetLocalAddr: TSockAddrIn;
    function GetBufferSize: integer;
    procedure SetWaitConnectionData(const Value: boolean);
  protected
    function _AddRef: integer;
    function _Release: integer;
  public
    constructor Create(); virtual;
    destructor Destroy; override;
    procedure Disconnect; virtual; abstract;

    property LocalHost: string read GetLocalHost;
    property LocalAddress: string read GetLocalAddress;
    property LocalPort: Integer read GetLocalPort;
    property LocalAddr: TSockAddrIn read GetLocalAddr;

    property RemoteHost: string read GetRemoteHost;
    property RemoteAddress: string read GetRemoteAddress;
    property RemotePort: Integer read GetRemotePort;
    property RemoteAddr: TSockAddrIn read GetRemoteAddr;

    property Handle: TSocket read FSocket;
    property Server: TCustomHPServerSocket read FServer;
    property Connected: LongBool read FConnected;
    property Buffer: PByte read FpConnectBuf;
    property BufferSize: integer read GetBufferSize;
    property ConnectionTime: Cardinal read GetConnectionTime;
{### 1.4.0.6 Added june, 30, 2009}
    property WaitConnectionData: boolean read FWaitConnectionData  write SetWaitConnectionData;
{### /1.4.0.6}
  end;

  THPServerClientSPL = class(TCustomHPServerClient)
  public
    procedure Disconnect; override;
    function WriteBuffer(const Buffers: TWsaBuf; BufCount: integer; CompletionKey: integer): Cardinal;
    function ReadBuffer(const Buffers: TWsaBuf; BufCount: integer; CompletionKey: integer): Cardinal;
  end;

  THPServerClient = class(TCustomHPServerClient)
  public
    procedure Disconnect; override;
    function WriteBuffer(var Buffers: TWsaBuf; BufCount: integer; CompletionKey: integer): integer;
    function ReadBuffer(var Buffers: TWsaBuf; BufCount: integer; CompletionKey: integer): integer;
    function Transmit(hFile: THandle; BytesToWrite, BytesPerSend: DWORD;
                      pTransmitBuffers: PTransmitFileBuffers;
                      CompletionKey: integer; DisconnectClient: boolean): integer;
  end;

  THPServerClientSPLClass = class of THPServerClientSPL;
  THPServerClientClass = class of THPServerClient;

  TThreadSafeStack = class
  private
    FCS: TRTLCriticalSection;
    FSpinCount: Cardinal;
    FClosed: integer;
    function GetClosed: boolean;
    procedure SetClosed(const Value: boolean);
    procedure SetSpinCount(const Value: Cardinal);
  protected
    FCount: integer;
    FCapacity: integer;
    procedure SetCapacity(const Value: integer); virtual; abstract;
  public
    constructor Create(ACapacity: integer);
    destructor Destroy; override;

    procedure Lock;
    procedure Unlock;
    procedure Clear; virtual; abstract;

    property Capacity: integer read FCapacity write SetCapacity;
    property Count: integer read FCount;
    property Closed: boolean read GetClosed write SetClosed;
    property SpinCount: Cardinal read FSpinCount write SetSpinCount;
  end;

  TSocketStack = class(TThreadSafeStack)
  private
    FSockets: array [0..$3FFF] of TSocket;
  protected
    procedure SetCapacity(const Value: integer); override;
  public
    function Push(ASocket: TSocket): boolean;
    function Pop(out ASocket: TSocket): boolean;
    procedure Clear; override;
  end;

{$IFDEF USE_SLIST}

  PHPSListEntry = ^THPSListEntry;
  THPSListEntry = record
    case byte of
    0: (Next: Pointer);
    1: (IOStruct: THPSockIOStruct);
  end;

  PHPSListEntrySPL = ^THPSListEntrySPL;
  THPSListEntrySPL = record
    case byte of
    0: (Next: Pointer);
    1: (IOStruct: THPSockIOStructSPL);
  end;

  TStructStack = class(TObject)
  private
    FSList: TSListHeader;
    FItemSize: integer;
    FCapacity: integer;
    FClosed: boolean;
  protected
    procedure SetCapacity(const Value: integer);
    function GetCount: integer;
  public
    constructor Create(ACapacity: integer; ItemSize: integer);
    destructor Destroy; override;
    procedure Push(PStruct: Pointer);
    function Pop: Pointer;
    procedure Clear;
    property Capacity: integer read FCapacity write SetCapacity;
    property Closed: boolean read FClosed write FClosed;
    property Count: integer read GetCount;
  end;

{$ELSE}

  PHPStructArray = ^THPStructArray;
  THPStructArray = array[0..MAXWORD] of Pointer;

  TStructStack = class(TThreadSafeStack)
  private
    FList: PHPStructArray;
    FItemSize: integer;
  protected
    procedure SetCapacity(const Value: integer); override;
  public
    constructor Create(ACapacity: integer; ItemSize: integer);
    destructor Destroy; override;
    procedure Push(PStruct: Pointer);
    function Pop: Pointer;
    procedure Clear; override;
  end;

{$ENDIF}

  TEnumClients = function(AClient: TCustomHPServerClient): boolean of object;

  TClientList = class(TThreadSafeStack)
  private
    FClient: TCustomHPServerClient;
    FNextEnum: TCustomHPServerClient;
  protected
    procedure SetCapacity(const Value: integer); override;
  public
    procedure Push(AClient: TCustomHPServerClient);
    function Pop: TCustomHPServerClient;
    function Remove(AClient: TCustomHPServerClient): integer;
    procedure Clear; override;
    procedure Enum(const EnumProc: TEnumClients);
  end;

  THPThreadList = class(TObject)
  private
    FList: TList;
    FCS: TRTLCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(Item: Pointer);
    function  LockList: TList;
    function Remove(Item: Pointer): boolean;
    procedure UnlockList;
  end;

  THPServConnectEvent = procedure(AClient: TCustomHPServerClient; pConnectionData: PByte; ConnectionDataLen: integer) of object;
  THPServBeforeAcceptEvent = procedure(AClient: TCustomHPServerClient; var ConnBufSize: integer) of object;
  THPServDisconnectEvent = procedure(AClient: TCustomHPServerClient) of object;
  THPServCompleteEvent = procedure(AClient: TCustomHPServerClient; BytesTransfered: Cardinal; CompletionKey: integer; Error: integer) of object;
  THPInitSocketEvent = procedure(Sender: TCustomHPServerSocket; Socket: TSocket) of object;
  THPLogMessageEvent = procedure(const Params: array of PAnsiChar; EventType, Category: Word; ID: DWORD) of object;
  THPLogMsgEvent = procedure(ModuleID, LogLevel: Byte; ThreadID, ClientID: Cardinal; const Line: String) of object;
  THPExceptionEvent = procedure(Client: TCustomHPServerClient; const Message: string; const ExceptClass: string; ExceptAddress: pointer) of object;
  THPServUserAsyncCall = procedure(Sender: TCustomHPServerSocket; UserKey: Cardinal; pUserData: pointer) of object;

  THPUserDeviceEvent = procedure(Sender: TCustomHPServerSocket; Success: boolean; BytesTransfered: Cardinal; CompletionKey: Cardinal; pOvp: POverlapped) of object;

  TAcceptorPriority = (apLow, apNormal, apHigh);

  TBindAddr = record
    SockFamily: integer;
    SockType: integer;
    AddrLen: integer;
    Addr: TSockAddrIn;
  end;

  TCustomHPServerSocket = class({$IFDEF WITH_GUI}TComponent{$ELSE}TObject{$ENDIF})
  private
    FListener: TSocket;
    FBindAddr: TBindAddr;
    FClientClass: THPServerClientSPLClass;
    FAcceptorsCount: integer;
    FMinAcceptors: integer;
    FActualAcceptors: integer;
    FAcceptThread: THPServerThread;
    FAcceptorPriority: TAcceptorPriority;

    FClientObjectsCount: integer;
    FConnections: TClientList;
    FClientStack: TClientList;
    FStructStack: TStructStack;

    FActive: LongBool;
    FServiceOrPort: string;
    FAddress: string;
    FClientsEvent: THandle;
    
    FAcceptEx: TAcceptEx;
    FDisconnectEx: TDisconnectEx;
    FGetAcceptExSockaddrs: TGetAcceptExSockaddrs;
    FTransmitFile: TTransmitFile;

    FOnCreateListener: THPInitSocketEvent;
    FOnCreateAcceptor: THPInitSocketEvent;
    FOnWriteComplete: THPServCompleteEvent;
    FOnReadComplete: THPServCompleteEvent;
    FOnClientConnect: THPServConnectEvent;
    FOnClientDisconnect: THPServDisconnectEvent;
    FOnLogMessage: THPLogMessageEvent;
    FOnLogMsg: THPLogMsgEvent;
    FOnThreadException: THPExceptionEvent;
    FOnClientBeforeAccept: THPServBeforeAcceptEvent;
    FFullExtensionsSupport: boolean;

    procedure GetExtensions;
    procedure IncreazeClients;
    procedure DecreazeClients;
    function CloseConnectionsProc(AClient: TCustomHPServerClient): boolean;
    function GetClientsCapacity: integer;
    function GetStuctCapacity: integer;
    procedure SetClientsCapacity(const Value: integer);
    procedure SetStuctCapacity(const Value: integer);
    procedure SetAcceptorsCount(const Value: integer);
    procedure SetOnClientConnect(const Value: THPServConnectEvent);
    procedure SetOnClientDisconnect(const Value: THPServDisconnectEvent);
    procedure SetOnCreateAcceptor(const Value: THPInitSocketEvent);
    procedure SetOnCreateListener(const Value: THPInitSocketEvent);
    procedure SetOnReadComplete(const Value: THPServCompleteEvent);
    procedure SetOnWriteComplete(const Value: THPServCompleteEvent);
    procedure SetAddress(const Value: string);
    procedure SetServiceOrPort(const Value: string);
    procedure SetOnLogMessage(const Value: THPLogMessageEvent);
    procedure SetOnLogMsg(const Value: THPLogMsgEvent);
    procedure SetOnThreadException(const Value: THPExceptionEvent);
    procedure SetOnClientBeforeAccept(const Value: THPServBeforeAcceptEvent);
    procedure SetAcceptorPriority(const Value: TAcceptorPriority);
    function GetConnectionsCount: integer;
    procedure SetMinAcceptors(Value: integer);
    procedure ClientAccepted;
  public
    constructor Create{$IFDEF WITH_GUI}(AOwner: TComponent){$ENDIF};
    destructor Destroy; override;

    procedure Open; virtual;
    procedure Close(Timeout: Cardinal); virtual; abstract;
    procedure EnumerateConnections(const Proc: TEnumClients);
    procedure LogMessage(const Params: array of PAnsiChar; EventType, Category: Word; ID: DWORD);
    procedure LogMsg(ModuleID, LogLevel: Byte; ClientID: Cardinal; const Line: String);

    property Active: LongBool read FActive;
    property ConnectionsCount: integer read GetConnectionsCount;

    property Address: string read FAddress write SetAddress;
    property ServiceOrPort: string read FServiceOrPort write SetServiceOrPort;
    property Port: string read FServiceOrPort write SetServiceOrPort;
    property ClientStackCapacity: integer read GetClientsCapacity  write SetClientsCapacity default DefClientsCapacity;
    property StuctStackCapacity: integer read GetStuctCapacity write SetStuctCapacity default DefStuctStackCapacity;
    property AcceptorsCount: integer read FAcceptorsCount write SetAcceptorsCount default DefAcceptorsCount;
    property MinimumAcceptors: integer read FMinAcceptors write SetMinAcceptors default DefMinAcceptors;
    property AcceptorPriority: TAcceptorPriority read FAcceptorPriority write SetAcceptorPriority default apNormal;
    property FullExtensionsSupport: boolean read FFullExtensionsSupport;
    property OnCreateListener: THPInitSocketEvent read FOnCreateListener write SetOnCreateListener;
    property OnCreateAcceptor: THPInitSocketEvent read FOnCreateAcceptor write SetOnCreateAcceptor;
    property OnClientBeforeAccept: THPServBeforeAcceptEvent read FOnClientBeforeAccept write SetOnClientBeforeAccept;
    property OnClientConnect: THPServConnectEvent read FOnClientConnect write SetOnClientConnect;
    property OnClientDisconnect: THPServDisconnectEvent read FOnClientDisconnect write SetOnClientDisconnect;
    property OnReadComplete: THPServCompleteEvent read FOnReadComplete write SetOnReadComplete;
    property OnWriteComplete: THPServCompleteEvent read FOnWriteComplete write SetOnWriteComplete;
    property OnLogMessage: THPLogMessageEvent read FOnLogMessage write SetOnLogMessage;
    property OnLogMsg: THPLogMsgEvent read FOnLogMsg write SetOnLogMsg;
    property OnThreadException: THPExceptionEvent read FOnThreadException write SetOnThreadException;
  end;

  THPServerSocketSPL = class(TCustomHPServerSocket)
  private
    FClientClass: THPServerClientSPLClass;

    function CloseConnectionsProc(AClient: TCustomHPServerClient): boolean;
    procedure SetClientClass(const Value: THPServerClientSPLClass);
  public
    constructor Create{$IFDEF WITH_GUI}(AOwner: TComponent){$ENDIF};
    destructor Destroy; override;
    procedure Open; override;
    procedure Close(Timeout: Cardinal); override;
    property ClientClass: THPServerClientSPLClass read FClientClass write SetClientClass;
  published
    property Address;
    property ServiceOrPort;
    property ClientStackCapacity;
    property StuctStackCapacity;
    property AcceptorsCount;
    property MinimumAcceptors;
    property AcceptorPriority;

    property OnCreateListener;
    property OnCreateAcceptor;
    property OnClientBeforeAccept;
    property OnClientConnect;
    property OnClientDisconnect;
    property OnReadComplete;
    property OnWriteComplete;
    property OnLogMessage;
    property OnLogMsg;
    property OnThreadException;
  end;

  THPServerSocket = class(TCustomHPServerSocket)
  private
    FClientClass: THPServerClientClass;
    FPort: TCompletionPort;

    FWorkThreads: integer;
{### 1.4.0.6 Added june, 30, 2009}
    FDecreaseTryCount: integer;
    FDecreaseCompleteEvent: THandle;
{### /1.4.0.6}
    FActiveThreads: integer;
    FMinWorkThreads: integer;
    FThreadsList: THPThreadList;
    FOnUserAsyncCall: THPServUserAsyncCall;
    FOnThreadEnd: TNotifyEvent;
    FOnThreadStart: TNotifyEvent;
{### 1.4.0.6 Added june, 30, 2009}
    FOnAcceptorEnd: TNotifyEvent;
    FOnAcceptorStart: TNotifyEvent;
{### /1.4.0.6}
    FDecreaseLock: integer;
    FOnDeviceCompletion: THPUserDeviceEvent;

    function CloseConnectionsProc(AClient: TCustomHPServerClient): boolean;
    procedure SetClientClass(const Value: THPServerClientClass);
    procedure SetMinWorkThreads(const Value: integer);
    procedure SetOnUserAsyncCall(const Value: THPServUserAsyncCall);
    procedure SetOnThreadEnd(const Value: TNotifyEvent);
    procedure SetOnThreadStart(const Value: TNotifyEvent);
    procedure SetOnDeviceCompletion(const Value: THPUserDeviceEvent);
    procedure SetOnAcceptorEnd(const Value: TNotifyEvent);
    procedure SetOnAcceptorStart(const Value: TNotifyEvent);
  public
    constructor Create{$IFDEF WITH_GUI}(AOwner: TComponent){$ENDIF};
    destructor Destroy; override;

    procedure Open; override;
    procedure Close(Timeout: Cardinal); override;
    procedure AddWorkThread;
    function DecreaseWorkThreads: boolean;
    function UserAsyncCall(UserKey: Cardinal; PUserData: Pointer): boolean;
    function BindUserDevice(hDevice: THandle; CompletionKey: TUserKeyRange): boolean;
    
    property ClientClass: THPServerClientClass read FClientClass write SetClientClass;
    property WorkThreads: integer read FWorkThreads;
    property ActiveThreads: integer read FActiveThreads;
  published
    property MinimumWorkThreads: integer read FMinWorkThreads write SetMinWorkThreads;
    property Address;
    property ServiceOrPort;
    property ClientStackCapacity;
    property StuctStackCapacity;
    property AcceptorsCount;
    property MinimumAcceptors;
    property AcceptorPriority;

    property OnCreateListener;
    property OnCreateAcceptor;
    property OnClientBeforeAccept;
    property OnClientConnect;
    property OnClientDisconnect;
    property OnReadComplete;
    property OnWriteComplete;
    property OnLogMessage;
    property OnLogMsg;
    property OnThreadException;
    property OnUserAsyncCall: THPServUserAsyncCall read FOnUserAsyncCall write SetOnUserAsyncCall;
    property OnUserDeviceCompletion: THPUserDeviceEvent read FOnDeviceCompletion write SetOnDeviceCompletion;
    property OnThreadStart: TNotifyEvent read FOnThreadStart write SetOnThreadStart;
    property OnThreadEnd: TNotifyEvent read FOnThreadEnd write SetOnThreadEnd;
{### 1.4.0.6 Added june, 30, 2009}
    property OnAcceptorStart: TNotifyEvent read FOnAcceptorStart write SetOnAcceptorStart;
    property OnAcceptorEnd: TNotifyEvent read FOnAcceptorEnd write SetOnAcceptorEnd;
{### /1.4.0.6}
  end;

{$IFDEF WITH_GUI}
procedure Register;
{$ENDIF}

implementation

{$IFDEF WITH_GUI}
procedure Register;
begin
  RegisterComponents('Internet', [THPServerSocket{, THPServerSocketSPL}]);
end;
{$ENDIF}

{$IFNDEF MINWINXP}
{$IFDEF USE_SLIST}
var
  SListFunc: TSListFunc = ();
{$ENDIF}
{$ENDIF}

var
  ThreadClientList: TList = nil;   // используется при логировании (доп. инфа)

const
  CP_TERMINATE     = 0;
  CP_IO            = 1;
  CP_DELETETHREAD  = 2;
  CP_USERASYNCCALL = 3;

type
  TAcceptThreadSPL = class(THPServerThread)
  private
    FServer: THPServerSocketSPL;
  protected
    procedure Execute; override;
  public
    constructor Create(Server: THPServerSocketSPL; CreateSyspended: boolean);
  end;

  TAcceptThread = class(THPServerThread)
  private
    FServer: THPServerSocket;
  protected
    procedure Execute; override;
  public
    constructor Create(Server: THPServerSocket; CreateSyspended: boolean);
  end;

  THPServerWorkThread = class(TThread)
  private
    FServer: THPServerSocket;
  protected
    procedure Execute; override;
  public
    constructor Create(Server: THPServerSocket; CreateSyspended: boolean);
    function WaitForTimeout(TimeOut: cardinal): boolean;
  end;

{ TThreadSafeStack }

constructor TThreadSafeStack.Create(ACapacity: integer);
begin
  InitializeCriticalSectionAndSpinCount(FCS, 128 or CS_Alloc_Event);
  Capacity := ACapacity;
end;

destructor TThreadSafeStack.Destroy;
begin
  Clear;
  DeleteCriticalSection(FCS);
  inherited;
end;

function TThreadSafeStack.GetClosed: boolean;
begin
  Result := FClosed <> 0;
end;

procedure TThreadSafeStack.Lock;
begin
  EnterCriticalSection(FCS);
end;

procedure TThreadSafeStack.SetClosed(const Value: boolean);
var
  I: integer;
begin
  if Value then I := 1 else I := 0;
  InterlockedExchange(FClosed, I);
end;

procedure TThreadSafeStack.SetSpinCount(const Value: Cardinal);
begin
  SetCriticalSectionSpinCount(FCS, Value);
  FSpinCount := Value;
end;

procedure TThreadSafeStack.Unlock;
begin
  LeaveCriticalSection(FCS);
end;

{ TSocketStack }

procedure TSocketStack.Clear;
var
  n: integer;
begin
  Lock;
  try
    for n := 0 to Pred(FCount) do closesocket(FSockets[n]);
    FCount := 0;
  finally
    Unlock;
  end;
end;

function TSocketStack.Pop(out ASocket: TSocket): boolean;
begin
  Lock;
  try
    Result := FCount > 0;
    if Result then begin
      Dec(FCount);
      ASocket := FSockets[FCount];
    end;
  finally
    Unlock;
  end;
end;

function TSocketStack.Push(ASocket: TSocket): boolean;
begin
  Lock;
  try
    Result := (FClosed = 0) and (FCount < FCapacity);
    if Result then begin
      FSockets[FCount] := ASocket;
      Inc(FCount);
    end;
  finally
    Unlock;
  end;
end;

procedure TSocketStack.SetCapacity(const Value: integer);
begin
  if (Value < 0) or (Value > SizeOf(FSockets)) then raise EHPServerException.Create('Invalid capacity value');
  InterlockedExchange(FCapacity, Value);
end;

{ TCustomHPServerSocket }

constructor TCustomHPServerSocket.Create{$IFDEF WITH_GUI}(AOwner: TComponent){$ENDIF};
begin
  inherited;
  FAcceptorPriority := apNormal;
  FClientClass := THPServerClientSPL;
  FClientStack := TClientList.Create(DefClientsCapacity);
  FConnections := TClientList.Create(-1);
  FAcceptorsCount := DefAcceptorsCount;
  FMinAcceptors := DefMinAcceptors;
  FClientsEvent := CreateEvent(nil, true, true, nil);
  if FClientsEvent = 0 then raise EHPServerException.Create(SysErrorMessage(GetLastError));
end;

destructor TCustomHPServerSocket.Destroy;
begin
  Close(INFINITE);
  FConnections.Free;
  FClientStack.Free;
  CloseHandle(FClientsEvent);
  inherited;
end;

function TCustomHPServerSocket.GetClientsCapacity: integer;
begin
  Result := FClientStack.Capacity;
end;

procedure TCustomHPServerSocket.GetExtensions;
var
  hWS32: THandle;
begin
  hWS32 := GetModuleHandle('wsock32.dll');
  @FAcceptEx := GetExtensionFunc(FListener, WSAID_ACCEPTEX);
  if not Assigned(FAcceptEx) then begin
    @FAcceptEx := GetProcAddress(hWS32, 'AcceptEx');
    if not Assigned(FAcceptEx) then raise EHPServerException.Create(sAcceptExNotFound);
  end;
  @FGetAcceptExSockaddrs := GetExtensionFunc(FListener, WSAID_GETACCEPTEXSOCKADDRS);
  if not Assigned(FGetAcceptExSockaddrs) then begin
    @FGetAcceptExSockaddrs := GetProcAddress(hWS32, 'GetAcceptExSockaddrs');
    if not Assigned(FGetAcceptExSockaddrs) then raise EHPServerException.Create(sGetAcceptExSockaddrsNotFound);
  end;
  @FTransmitFile := GetExtensionFunc(FListener, WSAID_TRANSMITFILE);
  @FDisconnectEx := GetExtensionFunc(FListener, WSAID_DISCONNECTEX);
  FFullExtensionsSupport := Assigned(FTransmitFile) and Assigned(FDisconnectEx);
end;

function TCustomHPServerSocket.GetStuctCapacity: integer;
begin
  Result := FStructStack.Capacity;
end;

procedure TCustomHPServerSocket.SetClientsCapacity(const Value: integer);
begin
  FClientStack.Capacity := Value;
end;

procedure TCustomHPServerSocket.SetAcceptorsCount(const Value: integer);
var
  Old: integer;
begin
  if Value > 0 then begin
    Old := InterlockedExchange(FAcceptorsCount, Value);
    if (Old < Value) and Assigned(FAcceptThread) then FAcceptThread.Notify;
  end;
end;

procedure TCustomHPServerSocket.SetOnClientConnect(const Value: THPServConnectEvent);
begin
  if not FActive then FOnClientConnect := Value;
end;

procedure TCustomHPServerSocket.SetOnClientDisconnect(const Value: THPServDisconnectEvent);
begin
  if not FActive then FOnClientDisconnect := Value;
end;

procedure TCustomHPServerSocket.SetOnCreateAcceptor(const Value: THPInitSocketEvent);
begin
  if not FActive then FOnCreateAcceptor := Value;
end;

procedure TCustomHPServerSocket.SetOnCreateListener(const Value: THPInitSocketEvent);
begin
  if not FActive then FOnCreateListener := Value;
end;

procedure TCustomHPServerSocket.SetOnReadComplete(const Value: THPServCompleteEvent);
begin
  if not FActive then FOnReadComplete := Value;
end;

procedure TCustomHPServerSocket.SetOnWriteComplete(const Value: THPServCompleteEvent);
begin
  if not FActive then FOnWriteComplete := Value;
end;

procedure TCustomHPServerSocket.SetStuctCapacity(const Value: integer);
begin
  FStructStack.Capacity := Value;
end;

procedure TCustomHPServerSocket.SetAddress(const Value: string);
begin
  if not FActive then FAddress := Value;
end;

procedure TCustomHPServerSocket.SetServiceOrPort(const Value: string);
begin
  if not FActive then FServiceOrPort := Value;
end;

function TCustomHPServerSocket.CloseConnectionsProc(AClient: TCustomHPServerClient): boolean;
begin
  Result := true;
  AClient.Disconnect;
end;

procedure TCustomHPServerSocket.DecreazeClients;
begin
  if InterlockedDecrement(FClientObjectsCount) = 0 then SetEvent(FClientsEvent);
end;

procedure TCustomHPServerSocket.IncreazeClients;
begin
  if InterlockedIncrement(FClientObjectsCount) = 1 then ResetEvent(FClientsEvent);
end;

procedure TCustomHPServerSocket.SetOnLogMessage(const Value: THPLogMessageEvent);
begin
  if not FActive then FOnLogMessage := Value;
end;

procedure TCustomHPServerSocket.LogMessage(const Params: array of PAnsiChar; EventType, Category: Word; ID: DWORD);
begin
  if Assigned(OnLogMessage) then OnLogMessage(Params, EventType, Category, ID);
end;

function GetThreadClientNumber(ThreadID: Cardinal): Cardinal;
begin
  if ThreadID = $FFFFFFFF then begin Result := $FFFFFFFF; Exit; end;
  if ThreadID = $FFFFFFFE then ThreadID := Windows.GetCurrentThreadId;
  if not Assigned(ThreadClientList) then begin
    ThreadClientList := TList.Create;
    ThreadClientList.Add(Pointer(MainThreadID));
    Result := 0;
    if ThreadID <> MainThreadID then begin
      ThreadClientList.Add(Pointer(ThreadID));
      Result := 1;
    end;
    Exit;
  end;
  Result := Cardinal(ThreadClientList.IndexOf(Pointer(ThreadID)));
  if Result = $FFFFFFFF then begin
    ThreadClientList.Add(Pointer(ThreadID));
    Result := ThreadClientList.Count - 1;
  end;
end;

procedure TCustomHPServerSocket.SetOnLogMsg(const Value: THPLogMsgEvent);
begin
  if not FActive then FOnLogMsg := Value;
end;

procedure TCustomHPServerSocket.LogMsg(ModuleID, LogLevel: Byte; ClientID: Cardinal; const Line: String);
begin
  if Assigned(OnLogMsg) then OnLogMsg(ModuleID, LogLevel, GetThreadClientNumber($FFFFFFFE), ClientID, Line);
end;

procedure TCustomHPServerSocket.SetOnThreadException(const Value: THPExceptionEvent);
begin
  if not FActive then FOnThreadException := Value;
end;

procedure TCustomHPServerSocket.SetOnClientBeforeAccept(const Value: THPServBeforeAcceptEvent);
begin
  if not FActive then FOnClientBeforeAccept  := Value;
end;

procedure TCustomHPServerSocket.Open;
var
  WD: WSAData;
  BindAddrInfo, P: PAddrInfo;
  n: integer;
begin
  IsMultiThread := true;

  if SOCKET_ERROR = WSAStartup(MakeWord(2, 2), WD) then
    raise EHPServerException.Create(SysErrorMessage(WSAGetLastError));

  FClientStack.Closed := false;
  FConnections.Closed := false;
  FStructStack.Closed := false;
//  if FConnections.Count = 0 then
  SetEvent(FClientsEvent);
  {$IFNDEF MINWINXP}
  if _IPv6Supported then begin
  {$ENDIF}
    BindAddrInfo := ResolveAddressAndPortV6(true, FAddress, FServiceOrPort, PF_INET, SOCK_STREAM);
    try
      n := 0;
      P := BindAddrInfo;
      while P <> nil do
      begin
        if n = FD_SETSIZE then
          raise ESockAddrError.Create('Too many addresses!');
        if (P.ai_family = PF_INET) or (P.ai_family = PF_INET6) then Break;
        Inc(n);
        P := P.ai_next;
      end;

      if P = nil then raise ESockAddrError.Create('Invalid address!');

      with P^ do
      begin
        FBindAddr.SockFamily := ai_family;
        FBindAddr.SockType := ai_socktype;
        FBindAddr.AddrLen := ai_addrlen;
        FBindAddr.Addr := ai_addr^;
      end;
    finally
      F_FreeAddrInfo(BindAddrInfo);
    end;
  {$IFNDEF MINWINXP}
  end else begin
    ResolveAddressAndPort(FAddress, FServiceOrPort, 'tcp', FBindAddr.Addr);
    FBindAddr.SockFamily := AF_INET;
    FBindAddr.SockType := SOCK_STREAM;
    FBindAddr.AddrLen := SizeOf(FBindAddr.Addr);
  end;
  {$ENDIF}

  with FBindAddr do FListener := socket(SockFamily, SockType, IPPROTO_IP);
  if INVALID_SOCKET = FListener then
  begin
    FListener := 0;
    raise EHPServerException.Create(SysErrorMessage(WSAGetLastError));
  end;
  if Assigned(OnCreateListener) then OnCreateListener(Self, FListener);

  GetExtensions;

  with FBindAddr do begin
    if SOCKET_ERROR = bind(FListener, Addr, AddrLen) then
      raise EHPServerException.Create(SysErrorMessage(WSAGetLastError));
  end;    
  if SOCKET_ERROR = listen(FListener, SOMAXCONN2) then
    raise EHPServerException.Create(SysErrorMessage(WSAGetLastError));
end;

procedure TCustomHPServerSocket.SetAcceptorPriority(const Value: TAcceptorPriority);
const
  Priorities: array [TAcceptorPriority] of Integer =
   (THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL);
begin
  FAcceptorPriority := Value;
  if FActive then SetThreadPriority(FAcceptThread.Handle, Priorities[Value]);
end;

procedure TCustomHPServerSocket.EnumerateConnections(const Proc: TEnumClients);
begin
  if FConnections <> nil then FConnections.Enum(Proc);
end;

function TCustomHPServerSocket.GetConnectionsCount: integer;
begin
  Result := FConnections.Count;
end;

procedure TCustomHPServerSocket.SetMinAcceptors(Value: integer);
begin
  if Value < 1 then Value := 1 else
  if Value > FAcceptorsCount then Value := AcceptorsCount;
  InterlockedExchange(FMinAcceptors, Value);
end;

procedure TCustomHPServerSocket.ClientAccepted;
var
  n: integer;
begin
  n := InterlockedDecrement(FActualAcceptors);
  if Active and (n < FMinAcceptors) then FAcceptThread.Notify;
end;

{ THPServerSocketSPL }

function Handle_IO_Error(PStruct: PHPSockIOStructSPL): DWORD; stdcall;
var
  P: PHPSockIOStructSPL;
  C: THPServerClientSPL;
  Key, Err: integer;
begin
  Result := 0;
  if PStruct = nil then Exit;
  C := THPServerClientSPL(PStruct.Client);
  try
    with PStruct^ do
    begin
      Key := CompletionKey;
      Err := Error;
      P := C.ExchangeStruct(PStruct);
      if P <> nil then C.Server.FStructStack.Push(P);
    end;

    case PStruct.OpCode of

      HPSO_READ:
      begin
        if Assigned(C.Server.OnReadComplete) then
          try
            C.Server.OnReadComplete(C, 0, Key, Err);
          except
            C.Disconnect;
            Err := WSAEWOULDBLOCK;
          end;
        if Err <> WSAEWOULDBLOCK then C.Disconnect;
      end;

      HPSO_WRITE:
      begin
        if Assigned(C.Server.OnWriteComplete) then
          try
            C.Server.OnWriteComplete(C, 0, Key, Err);
          except
            C.Disconnect;
            Err := WSAEWOULDBLOCK;
          end;
        if Err <> WSAEWOULDBLOCK then C.Disconnect;
      end;

    end;
  finally
    C._Release;
  end;
end;

function Queue_IO_Item(PStruct: PHPSockIOStructSPL): DWORD; stdcall;
var
  dw, Flg: Cardinal;
  C: THPServerClientSPL;
begin
  Result := 0;
  if PStruct = nil then Exit;

  C := THPServerClientSPL(PStruct.Client);
  try
    try
      case PStruct.OpCode of

        HPSO_READ:
        begin
          Flg := 0;
          with PStruct^, Client do
          begin
            _AddRef;
            if WSARecv(Handle, Buffers[0], BuffersCount, dw, Flg, @Ovp, nil) = SOCKET_ERROR then begin
              Error := WSAGetLastError;
              if Error <> WSA_IO_PENDING then QueueUserWorkItem(@Handle_IO_Error, PStruct, WT_EXECUTEDEFAULT);
            end;
          end;
        end; // HPSO_READ

        HPSO_WRITE:
        begin
          with PStruct^, Client do
          begin
            _AddRef;
            if WSASend(Handle, Buffers[0], BuffersCount, dw, 0, @Ovp, nil) = SOCKET_ERROR then
            begin
              Error := WSAGetLastError;
              if Error <> WSA_IO_PENDING then QueueUserWorkItem(@Handle_IO_Error, PStruct, WT_EXECUTEDEFAULT);
            end;
          end;
        end; // HPSO_WRITE
      end; // case
    finally
      C._Release;
    end;
  except
    on E: Exception do
      if Assigned(C.Server.OnThreadException) then
        C.Server.OnThreadException(C, E.Message, E.ClassName, ExceptAddr);
  end;
end;


procedure Handle_IO_Complete(dwErrorCode: integer; BytesTransfered: DWORD;  pOvp: POverlapped); stdcall;
var
  PStruct: PHPSockIOStructSPL absolute pOvp;
  P: PHPSockIOStructSPL;
  s: TSocket;
  C: THPServerClientSPL;
  Key: integer;
begin
  if PStruct = nil then exit;
  C := THPServerClientSPL(PStruct.Client);
  try
    try
      FillChar(PStruct.Ovp, sizeof(PStruct.Ovp), 0);

      case PStruct.OpCode of

        HPSO_ACCEPT:
        begin
          C.Server.ClientAccepted;
          if not C.Server.Active or (dwErrorCode <> ERROR_SUCCESS) then
          begin
            s := C.ExtractSocket;
            closesocket(s);
            C.Server.FClientStack.Push(C);
            C.Server.FStructStack.Push(PStruct);
          end else
          begin
            C.FConnected := true;
            C.Server.FConnections.Push(C);
            C.ExtractAddresses;
            P := C.ExchangeStruct(PStruct);
            if P <> nil then C.Server.FStructStack.Push(P);
            if Assigned(C.Server.OnClientConnect) then
            try
              C.Server.OnClientConnect(C, C.FpConnectBuf, integer(BytesTransfered));
            except
              C.Disconnect;
            end;
          end;
        end; // HPSO_ACCEPT

        HPSO_READ:
        begin
          Key := PStruct.CompletionKey;
          P := C.ExchangeStruct(PStruct);
          if P <> nil then C.Server.FStructStack.Push(P);
          if Assigned(C.Server.OnReadComplete) then
          try
            C.Server.OnReadComplete(C, BytesTransfered, Key, dwErrorCode);
          except
            C.Disconnect;
          end;
          if dwErrorCode <> ERROR_SUCCESS then begin
            if dwErrorCode <> WSAEWOULDBLOCK then C.Disconnect;
          end else begin
            if BytesTransfered = 0 then C.Disconnect;
          end;  
        end; // HPSO_READ

        HPSO_WRITE:
        begin
          Key := PStruct.CompletionKey;
          P := C.ExchangeStruct(PStruct);
          if P <> nil then C.Server.FStructStack.Push(P);
          if Assigned(C.Server.OnWriteComplete) then
          try
            C.Server.OnWriteComplete(C, BytesTransfered, Key, dwErrorCode);
          except
            C.Disconnect;
          end;
          if dwErrorCode <> ERROR_SUCCESS then begin
            if dwErrorCode <> WSAEWOULDBLOCK then C.Disconnect;
          end else begin
            if BytesTransfered = 0 then C.Disconnect;
          end;  
        end; // HPSO_WRITE

      end;
    finally
      C._Release;
    end;
  except
    on E: Exception do
      if Assigned(C.Server.OnThreadException) then
        C.Server.OnThreadException(C, E.Message, E.ClassName, ExceptAddr);
  end;
end;


procedure THPServerSocketSPL.Close(Timeout: Cardinal);
var
  StartTime, TimeVal: int64;

  function GetNextTimeout: Cardinal;
  begin
    if Timeout <> INFINITE then begin
      TimeVal := GetTickCount;
      if TimeVal < StartTime then TimeVal := TimeVal + MAXDWORD + 1;
      TimeVal := TimeVal - StartTime;
      if TimeVal < Timeout then Result := cardinal(Timeout - TimeVal)
      else Result := 0;
    end else begin
      Result := INFINITE;
    end;  
  end;

begin
  if not longBool(InterlockedExchange(integer(FActive), integer(LongBool(false)))) then Exit;

  FClientStack.Closed := true;
  FStructStack.Closed := true;

  StartTime := GetTickCount;
  closesocket(InterlockedExchange(FListener, 0));
  FAcceptThread.Terminate;


  FConnections.Enum(CloseConnectionsProc);
  WaitForSingleObject(FClientsEvent, GetNextTimeout);

  if not FAcceptThread.WaitForTimeout(GetNextTimeout) then TerminateThread(FAcceptThread.Handle, 1);
  FreeAndNil(FAcceptThread);

  FStructStack.Clear;

  WSACleanup;
end;

procedure THPServerSocketSPL.Open;
begin
  if longBool(InterlockedExchange(integer(FActive), integer(LongBool(true)))) then Exit;
  try
    inherited;
    if not BindIoCompletionCallback(THandle(FListener), @Handle_IO_Complete, 0)
      then raise EHPServerException.Create(SysErrorMessage(GetLastError));
    FAcceptThread := TAcceptThreadSPL.Create(Self, false);
    AcceptorPriority := FAcceptorPriority;
  except
    if FListener <> 0 then closesocket(FListener);
    FListener := 0;
    InterlockedExchange(integer(FActive), integer(LongBool(false)));
    raise;
  end;
end;

procedure THPServerSocketSPL.SetClientClass(
const
  Value: THPServerClientSPLClass);
begin
  if not FActive then begin
    if Value = nil then begin
      FClientClass := THPServerClientSPL;
    end else
    if Value.InheritsFrom(THPServerClientSPL) then begin
      FClientClass := Value;
    end else begin
      raise EHPServerException.Create(sClassInvalid);
    end;  
  end;
end;

function THPServerSocketSPL.CloseConnectionsProc(AClient: TCustomHPServerClient): boolean;
begin
  Result := true;
  AClient.Disconnect;
end;

constructor THPServerSocketSPL.Create{$IFDEF WITH_GUI}(AOwner: TComponent){$ENDIF};
begin
  inherited;
  FStructStack := TStructStack.Create(DefStuctStackCapacity, SizeOf(THPSockIOStructSPL));
end;

destructor THPServerSocketSPL.Destroy;
begin
  inherited;
  FStructStack.Free;
end;

{ TStructStack }

{$IFDEF USE_SLIST}

procedure TStructStack.Clear;
var
  P: Pointer;
begin
  repeat
    {$IFDEF MINWINXP}
    P := SList_PopSListEntry(@FSList);
    {$ELSE}
    P := SListFunc.PopSListEntry(@FSList);
    {$ENDIF}
    if P = nil then Break;
    FreeMem(P);
  until false;
end;

constructor TStructStack.Create(ACapacity, ItemSize: integer);
begin
  {$IFNDEF MINWINXP}
  if not SListFunc.Presents then raise EHPServerException.Create(SysErrorMessage(ERROR_OLD_WIN_VERSION));
  SListFunc.InitHeader(@FSList);
  {$ELSE}
  SList_InitHeader(@FSList);
  {$ENDIF}
  Capacity := ACapacity;
  FItemSize := ItemSize;
end;

destructor TStructStack.Destroy;
begin
  {$IFNDEF MINWINXP}
  if SListFunc.Presents then
  {$ENDIF}
  Clear;
end;

function TStructStack.Pop: Pointer;
begin
  {$IFNDEF MINWINXP}
  Result := SListFunc.PopSListEntry(@FSList);
  {$ELSE}
  Result := SList_PopSListEntry(@FSList);
  {$ENDIF}
  if not Assigned(Result) then Result := AllocMem(FItemSize);
  if Assigned(Result) then FillChar(Result^, FItemSize, 0);
end;

function TStructStack.GetCount: integer;
begin
  {$IFNDEF MINWINXP}
  Result := SListFunc.QueryDepth(@FSList);
  {$ELSE}
  Result := SList_QueryDepth(@FSList);
  {$ENDIF}
end;

procedure TStructStack.Push(PStruct: Pointer);
begin
  if not Assigned(PStruct) then exit;
  if not FClosed then begin
    {$IFNDEF MINWINXP}
    if FCapacity > SListFunc.QueryDepth(@FSList) then begin
      SListFunc.PushSListEntry(@FSList, PStruct);
      PStruct := nil;
    end;
    {$ELSE}
    if FCapacity > SList_QueryDepth(@FSList) then begin
      SList_PushSListEntry(@FSList, PStruct);
      PStruct := nil;
    end;
    {$ENDIF}
  end;
  if Assigned(PStruct) then FreeMem(PStruct);
end;

procedure TStructStack.SetCapacity(const Value: integer);
begin
  if (Value < 0) or (Value > High(Word)) then raise EHPServerException.Create('Invalid capacity value');
  FCapacity := Value;
end;

{$ELSE}

procedure TStructStack.Clear;
var
  n: integer;
  p: pointer;
begin
  Lock;
  try
    for n := 0 to Pred(FCount) do begin
      p := FList[n];
      FreeMem(P);
    end;
    FCount := 0;
  finally
    Unlock;
  end;
end;

constructor TStructStack.Create(ACapacity, ItemSize: integer);
begin
  inherited Create(ACapacity);
  FItemSize := ItemSize;
end;

destructor TStructStack.Destroy;
begin
  inherited;
  Freemem(FList);
end;

function TStructStack.Pop: Pointer;
begin
  Lock;
  try
    if FCount > 0 then begin
      Dec(FCount);
      Result := FList[FCount];
    end else
      Result := nil;
  finally
    Unlock;
  end;

  if not Assigned(Result) then Result := AllocMem(FItemSize);
  if Assigned(Result) then FillChar(Result^, FItemSize, 0);
end;

procedure TStructStack.Push(PStruct: Pointer);
begin
  if not Assigned(PStruct) then exit;

  if FClosed = 0 then begin
    Lock;
    try
      if FCount < FCapacity then begin
        FList[FCount] := PStruct;
        Inc(FCount);
        PStruct := nil;
      end;
    finally
      Unlock;
    end;
  end;
  
  if Assigned(PStruct) then FreeMem(PStruct);
end;

procedure TStructStack.SetCapacity(const Value: integer);
begin
  if (Value < 0) or (Value > SizeOf(THPStructArray)) then raise EHPServerException.Create('Invalid capacity value');
  Lock;
  try
    if Value > FCapacity then ReallocMem(FList, Value * SizeOf(FList[0]));
    FCapacity := Value;
  finally
    Unlock;
  end;
end;

{$ENDIF}

{ TClientList }

procedure TClientList.Clear;
begin
  /// Temporary stub
end;

procedure TClientList.Enum(const EnumProc: TEnumClients);
var
  C: TCustomHPServerClient;
  ContFlg: boolean;
begin
  if not Assigned(EnumProc) then Exit;
  c := FClient;
  repeat
    Lock;
    try
      ContFlg := Assigned(C);
      if ContFlg then begin
        FNextEnum := C.FNext;
        C._AddRef;
        ContFlg := EnumProc(C);
        C._Release;
        C := FNextEnum;
      end;
    finally
      Unlock;
    end;
  until not ContFlg;
end;

function TClientList.Pop: TCustomHPServerClient;
begin
  Result := nil;
  Lock;
  try
    if FCount > 0 then begin
      if FClient = FNextEnum then FNextEnum := FClient.FNext;
      Result := FClient;
      FClient := Result.FNext;
      if Assigned(FClient) then FClient.FPrev := nil;
      Result.FList := nil;
      Dec(FCount);
    end;
  finally
    Unlock;
  end;
end;

procedure TClientList.Push(AClient: TCustomHPServerClient);
begin
  if not Assigned(AClient) then exit;
  if FClosed = 0 then
  begin
    Lock;
    try
      if (FCapacity = -1) or (FCount < FCapacity) then begin
        AClient.FNext := FClient;
        if Assigned(FClient) then FClient.FPrev := AClient;
        AClient.FPrev := nil;
        AClient.FList := Self;
        FClient := AClient;
        AClient := nil;
        Inc(FCount);
      end;
    finally
      Unlock;
    end;
  end;
  if Assigned(AClient) then AClient._Release;
end;

function TClientList.Remove(AClient: TCustomHPServerClient): integer;
begin
  Result := -1;
  if not Assigned(AClient) then Exit;
  if AClient.FList <> Self then exit;
  Lock;
  try
    if AClient = FNextEnum then FNextEnum := AClient.FNext;
    if AClient = FClient then FClient := AClient.FNext;
    if Assigned(AClient.FPrev) then AClient.FPrev.FNext := AClient.FNext;
    if Assigned(AClient.FNext) then AClient.FNext.FPrev := AClient.FPrev;
    AClient.FList := nil;
    AClient.FNext := nil;
    AClient.FPrev := nil;
    Dec(FCount);
    Result := FCount;
  finally
    Unlock;
  end;
end;

procedure TClientList.SetCapacity(const Value: integer);
begin
  if Value < -1 then raise EHPServerException.Create('Invalid capacity value');
  InterlockedExchange(FCapacity, Value);
end;

{ THPThreadList }

procedure THPThreadList.Add(Item: Pointer);
begin
  with LockList do
  try
    Add(Item);
  finally
    UnlockList;
  end;
end;

constructor THPThreadList.Create;
begin
  FList := TList.Create;
  InitializeCriticalSectionAndSpinCount(FCS, 128 or CS_Alloc_Event);
end;

destructor THPThreadList.Destroy;
begin
  DeleteCriticalSection(FCS);
  FList.Free;
  inherited;
end;

function THPThreadList.LockList: TList;
begin
  EnterCriticalSection(FCS);
  Result := FList;
end;

function THPThreadList.Remove(Item: Pointer): boolean;
begin
  with LockList do
  try
    Result := Remove(Item) >= 0;
  finally
    UnlockList;
  end;
end;

procedure THPThreadList.UnlockList;
begin
  LeaveCriticalSection(FCS);
end;

{ TCustomHPServerClient }

function TCustomHPServerClient._AddRef: integer;
begin
  Result := InterlockedIncrement(FRefCount);
end;

function TCustomHPServerClient._Release: integer;
begin
  Result := InterlockedDecrement(FRefCount);
  if 0 = Result then Destroy;
end;

constructor TCustomHPServerClient.Create;
begin
  FServer.IncreazeClients;
  FRefCount := 1;
  FWaitConnectionData := true;
end;

destructor TCustomHPServerClient.Destroy;
var
  s: TSocket;
  p: PHPSockIOStructSPL;
begin
  s := ExtractSocket;
  if s <> 0 then closesocket(s);
  p := ExchangeStruct(nil);
  if p <> nil then FreeMem(p);
  FreeMem(FpConnectBuf);
  inherited;
  FServer.DecreazeClients;
end;

function TCustomHPServerClient.ExchangeStruct(P: Pointer): Pointer;
begin
  integer(Result) := InterlockedExchange(integer(FPStruct), integer(P));
end;

procedure TCustomHPServerClient.ExtractAddresses;
var
  PLoc, PRem: PSockAddrIn;
  LLoc, LRem: integer;
begin
  Server.FGetAcceptExSockaddrs(FpConnectBuf, FAddrOffset, Addr_Buf_Len, Addr_Buf_Len, PLoc, LLoc, PRem, LRem);
  if SizeOf(FLocalAddr)  = LLoc then FLocalAddr  := PLoc^ else FillChar(FLocalAddr,  SizeOf(FLocalAddr),  0);
  if SizeOf(FRemoteAddr) = LRem then FRemoteAddr := PRem^ else FillChar(FRemoteAddr, SizeOf(FRemoteAddr), 0);
end;

function TCustomHPServerClient.ExtractSocket: TSocket;
begin
  Result := InterlockedExchange(FSocket, 0);
end;

function TCustomHPServerClient.GetConnectionTime: Cardinal;
var
  OptLen: integer;
begin
  Optlen := sizeof(Result);
  getsockopt(Handle, SOL_SOCKET, SO_CONNECT_TIME, @Result, OptLen);
end;

function TCustomHPServerClient.GetLocalAddress: string;
begin
  Result := inet_ntoa(FLocalAddr.sin_addr);
end;

function TCustomHPServerClient.GetLocalHost: string;
var
  NameBuf: array[0..255] of Char;
begin
  if gethostname(NameBuf, SizeOf(NameBuf)) = ERROR_SUCCESS
    then Result := NameBuf else Result := '';
end;

function TCustomHPServerClient.GetLocalPort: Integer;
begin
  Result := ntohs(FLocalAddr.sin_port);
end;

function TCustomHPServerClient.GetRemoteAddr: TSockAddrIn;
begin
  Result := FRemoteAddr;
end;

function TCustomHPServerClient.GetRemoteAddress: string;
begin
  Result := inet_ntoa(FRemoteAddr.sin_addr);
end;

function TCustomHPServerClient.GetRemoteHost: string;
var
  pEnt: PHostEnt;
begin
  Result := '';
  if not Connected then Exit;
  pEnt := gethostbyaddr(@FRemoteAddr.sin_addr, SizeOf(TInAddr), AF_INET);
  if nil <> pEnt then Result := pEnt.h_name;
end;

function TCustomHPServerClient.GetRemotePort: Integer;
begin
  Result := ntohs(FRemoteAddr.sin_port);
end;

procedure TCustomHPServerClient.ReallocConnBuf(NewSize: integer);
begin
  if (FpConnectBuf = nil) or (NewSize <> BufferSize) then begin
    FreeMem(FpConnectBuf);
    FpConnectBuf := nil;
    FConnBufSize := 0;
    GetMem(FpConnectBuf, NewSize + 2 * Addr_Buf_Len);
    FConnBufSize := NewSize;
  end;
end;

function TCustomHPServerClient.GetLocalAddr: TSockAddrIn;
begin
  Result := FLocalAddr;
end;

function TCustomHPServerClient.GetBufferSize: integer;
begin
  if Connected then Result := FConnBufSize + Addr_Buf_Len*2  else Result := FConnBufSize;
end;

procedure TCustomHPServerClient.SetWaitConnectionData(const Value: boolean);
begin
  FWaitConnectionData  := Value;
end;

{ THPServerClientSPL }

procedure THPServerClientSPL.Disconnect;
var
  P: PHPSockIOStructSPL;
  s: TSocket;
  b: boolean;
begin
  _AddRef;
  if not LongBool(InterlockedExchange(integer(FConnected), integer(LongBool(false)))) then begin
    _Release;
    Exit;
  end;

  FServer.FConnections.Remove(Self);
  P := ExchangeStruct(nil);
  if P <> nil then Server.FStructStack.Push(P);

  b := Assigned(Server.FDisconnectEx);
  if b then b := FServer.FDisconnectEx(Handle, nil, TF_REUSE_SOCKET, 0);

  if not b then begin
    s := ExtractSocket;
    closesocket(s);
  end;

  if Assigned(FServer.OnClientDisconnect) then
  try
    FServer.OnClientDisconnect(Self);
  except
    _Release;
    _Release;
    Exit;
  end;

  FServer.FClientStack.Push(Self);
        
  _Release;
end;

function THPServerClientSPL.ReadBuffer(const Buffers: TWsaBuf; BufCount, CompletionKey: integer): Cardinal;
var
  P: PHPSockIOStructSPL;
begin
  _AddRef;
  if BufCount > MAX_WSA_BUFFERS then begin
    Result := ERROR_INVALID_PARAMETER;
    _Release;
    Exit;
  end;

  p := ExchangeStruct(nil);
  if P = nil then FServer.FStructStack.Pop;
  if P = nil then begin
    Result := ERROR_OUTOFMEMORY;
    _Release;
    Exit;
  end;

  FillChar(P.Ovp, SizeOf(P.Ovp), 0);
  P.Client := Self;
  P.BuffersCount := BufCount;
  Move(Buffers, P.Buffers, BufCount * SizeOf(Buffers));
  P.CompletionKey := CompletionKey;
  P.OpCode := HPSO_READ;
  if QueueUserWorkItem(@Queue_IO_Item, P, WT_EXECUTEINIOTHREAD) then begin
    Result := ERROR_SUCCESS;
  end else begin
    Result := GetLastError;
    _Release;
  end;
end;

function THPServerClientSPL.WriteBuffer(const Buffers: TWsaBuf; BufCount, CompletionKey: integer): Cardinal;
var
  P: PHPSockIOStructSPL;
begin
  _AddRef;
  if BufCount > MAX_WSA_BUFFERS then begin
    Result := ERROR_INVALID_PARAMETER;
    _Release;
    Exit;
  end;

  p := ExchangeStruct(nil);
  if P = nil then FServer.FStructStack.Pop;
  if P = nil then begin
    Result := ERROR_OUTOFMEMORY;
    _Release;
    Exit;
  end;

  FillChar(P.Ovp, SizeOf(P.Ovp), 0);
  P.Client := Self;
  P.BuffersCount := BufCount;
  Move(Buffers, P.Buffers, BufCount * SizeOf(Buffers));
  P.CompletionKey := CompletionKey;
  P.OpCode := HPSO_WRITE;
  if QueueUserWorkItem(@Queue_IO_Item, P, WT_EXECUTEINIOTHREAD) then begin
    Result := ERROR_SUCCESS;
  end else begin
    Result := GetLastError;
    _Release;
  end;
end;

{ THPServerThread }

procedure THPServerThread.ClearClientsStack(const Stack: TClientList);
var
  C: TCustomHPServerClient;
begin
  repeat
    C := Stack.Pop;
    if C = nil then break;
    try
      C._Release;
    except
    end;
  until false;
end;

constructor THPServerThread.Create(CreateSyspended: boolean);
begin
  FEvent := CreateEvent(nil, false, true, nil);
  inherited Create(CreateSyspended);
end;

destructor THPServerThread.Destroy;
begin
  CloseHandle(FEvent);
  inherited;
end;

procedure THPServerThread.Notify;
begin
  SetEvent(FEvent);
end;

procedure THPServerThread.Terminate;
begin
  inherited Terminate;
  Notify;
end;

function THPServerThread.WaitForTimeout(TimeOut: cardinal): boolean;
begin
  Result := WaitForSingleObject(Handle, TimeOut) = WAIT_OBJECT_0;
end;

{ TAcceptThreadSPL }

constructor TAcceptThreadSPL.Create(Server: THPServerSocketSPL; CreateSyspended: boolean);
begin
  FServer := Server;
  inherited Create(CreateSyspended);
end;

procedure TAcceptThreadSPL.Execute;
var
  s: TSocket;
  PStruct: PHPSockIOStructSPL;
  Received, RecBufSize: Cardinal;
  Acceptable: bool;
  BufSz: integer;
begin
  repeat
    WaitForSingleObject(FEvent, INFINITE);
    if Terminated then Break;

    with FServer do
    while FActualAcceptors < FAcceptorsCount do begin
      if Terminated then Break;
      pStruct := FStructStack.Pop;
      if PStruct = nil then Break;
      FillChar(PStruct.Ovp, sizeOf(pStruct.Ovp), 0);
      PStruct.OpCode := HPSO_ACCEPT;
      PStruct.Client := THPServerClientSPL(FClientStack.Pop);
      if PStruct.Client = nil then begin
        try
          TObject(PStruct.Client) := FClientClass.NewInstance;
          PStruct.Client.FServer := FServer;
          PStruct.Client.Create();
        except
          PStruct.Client := nil;
          FStructStack.Push(PStruct);
          Break;
        end;
      end;  

      PStruct.Client._AddRef;
      PStruct.Client.FConnected := false;

      Acceptable := PStruct.Client.Handle <> 0;
      if not Acceptable then begin
        with FBindAddr do s := socket(SockFamily, SockType, IPPROTO_IP);
        PStruct.Client.FSocket := s;
        Acceptable := s <> INVALID_SOCKET;
        if Acceptable and Assigned(OnCreateAcceptor) then begin
          try
            OnCreateAcceptor(FServer, s);
          except
            closesocket(s);
            Acceptable := false;
          end;
        end;  
        if Acceptable then
          Acceptable := BindIoCompletionCallback(s, @Handle_IO_Complete, 0);
      end;

      if Acceptable then begin
        BufSz := PStruct.Client.BufferSize;
        try
          if Assigned(FServer.OnClientBeforeAccept) then FServer.OnClientBeforeAccept(PStruct.Client, BufSz);
          if BufSz < 0 then BufSz := 0;
          PStruct.Client.ReallocConnBuf(BufSz);
        except
          FreeAndNil(PStruct.Client);
          FStructStack.Push(PStruct);
          break;
        end;

        with PStruct.Client do
        begin
{### 1.4.0.6 Changed june, 30, 2009}
          if WaitConnectionData then RecBufSize := Cardinal(FConnBufSize) else RecBufSize := 0;
          FAddrOffset := RecBufSize;    
          Acceptable := FServer.FAcceptEx(FListener, Handle,
                                          FpConnectBuf, RecBufSize, Addr_Buf_Len,
                                          Addr_Buf_Len, Received, @PStruct.Ovp);
{### /1.4.0.6}
        end;
        Acceptable := Acceptable or (WSAGetLastError = WSA_IO_PENDING);
      end;

      if not Acceptable then begin
        s := PStruct.Client.ExtractSocket;
        if s <> 0 then closesocket(s);
        FStructStack.Push(PStruct);
        FClientStack.Push(PStruct.Client);
        PStruct.Client._Release;
        Break;
      end;

      InterlockedIncrement(FActualAcceptors);
    end;

  until Terminated;

  ClearClientsStack(FServer.FClientStack);
end;

{ TAcceptThread }

constructor TAcceptThread.Create(Server: THPServerSocket; CreateSyspended: boolean);
begin
  FServer := Server;
  inherited Create(CreateSyspended);
end;

procedure TAcceptThread.Execute;
var
  s: TSocket;
  PStruct: PHPSockIOStruct;
  Received, RecBufSize: Cardinal;
  Acceptable: bool;
  BufSz: integer;
begin
{### 1.4.0.6 Added june, 30, 2009}
  if Assigned(FServer.OnAcceptorStart) then FServer.OnAcceptorStart(FServer);
{### /1.4.0.6}
  repeat
    WaitForSingleObject(FEvent, INFINITE);
    if Terminated then Break;

    with FServer do
    while FActualAcceptors < FAcceptorsCount do begin
      if Terminated then Break;
      pStruct := FStructStack.Pop;
      if PStruct = nil then Break;
      FillChar(PStruct.Ovp, sizeOf(pStruct.Ovp), 0);
      PStruct.OpCode := HPSO_ACCEPT;
      PStruct.Client := THPServerClient(FClientStack.Pop);
      if PStruct.Client = nil then begin
        try
          TObject(PStruct.Client) := FClientClass.NewInstance;
          PStruct.Client.FServer := FServer;
          PStruct.Client.Create();
        except
          PStruct.Client := nil;
          FStructStack.Push(PStruct);
          Break;
        end;
      end;
      
      PStruct.Client._AddRef;
      PStruct.Client.FConnected := false;

      Acceptable := PStruct.Client.Handle <> 0;
      if not Acceptable then begin
        with FBindAddr do s := socket(SockFamily, SockType, IPPROTO_IP);
        Acceptable := s <> INVALID_SOCKET;
        if Acceptable then
        begin
          PStruct.Client.FSocket := s;
          if Assigned(OnCreateAcceptor) then begin
            try
              OnCreateAcceptor(FServer, s);
            except
              Acceptable := false;
            end;
          end;  
          if Acceptable then
            Acceptable := FPort.AddDevice(THandle(s), CP_IO);
        end;
      end;

      if Acceptable then begin
        BufSz := PStruct.Client.BufferSize;
        try
          if Assigned(FServer.OnClientBeforeAccept) then FServer.OnClientBeforeAccept(PStruct.Client, BufSz);
          if BufSz < 0 then BufSz := 0;
          PStruct.Client.ReallocConnBuf(BufSz);
        except
          FreeAndNil(PStruct.Client);
          FStructStack.Push(PStruct);
          break;
        end;
        with PStruct.Client do
        begin
{### 1.4.0.6 Changed june, 30, 2009}
          if WaitConnectionData then RecBufSize := Cardinal(FConnBufSize) else RecBufSize := 0;
          FAddrOffset := RecBufSize;
          Acceptable := FServer.FAcceptEx(FListener, Handle,
                                          FpConnectBuf, RecBufSize, Addr_Buf_Len,
                                          Addr_Buf_Len, Received, @PStruct.Ovp);
{### /1.4.0.6}
        end;
        Acceptable := Acceptable or (WSAGetLastError = WSA_IO_PENDING);
        if not Acceptable then
          OutputDebugString(PChar('Accept error = ' + IntToStr(WSAGetLastError)));
      end;

      if not Acceptable then begin
        s := PStruct.Client.ExtractSocket;
        if s <> 0 then closesocket(s);
        FClientStack.Push(PStruct.Client);
        FStructStack.Push(PStruct);
        PStruct.Client._Release;
{### 1.4.0.6 Added june, 30, 2009}
        Sleep(100);
{### /1.4.0.6}
        Continue;
//        Break;
      end;

      InterlockedIncrement(FActualAcceptors);
    end;

  until Terminated;

  ClearClientsStack(FServer.FClientStack);
{### 1.4.0.6 Added june, 30, 2009}
  if Assigned(FServer.OnAcceptorEnd) then FServer.OnAcceptorEnd(FServer);
{### /1.4.0.6}
end;

{ THPServerClient }

procedure THPServerClient.Disconnect;
var
  P: PHPSockIOStruct;
  s: TSocket;
  b: boolean;
  ErrCode: integer;
begin
  _AddRef;
  if not LongBool(InterlockedExchange(integer(FConnected), integer(LongBool(false)))) then
  begin
    _Release;
    Exit;
  end;

  P := ExchangeStruct(nil);
  if P = nil then P := Server.FStructStack.Pop;
  b := Assigned(P);
  if b then
  begin
    FillChar(P.Ovp, SizeOf(P.Ovp), 0);
    P.CompletionKey := 0;
    P.OpCode := HPSO_DISCONNECT;
    P.Client := Self;
    b := Assigned(Server.FDisconnectEx);
  end;

  if b then
  begin
    b := FServer.FDisconnectEx(Handle, POverlapped(P), TF_REUSE_SOCKET, 0);
    ErrCode := WSAGetLastError;
    if not b then b := (WSA_IO_PENDING = ErrCode);
  end;

  if not b then
  begin
    if P <> nil then Server.FStructStack.Push(P);
    s := ExtractSocket;
    closesocket(s);
    Server.FConnections.Remove(Self);
    if Assigned(FServer.OnClientDisconnect) then begin
      try
        FServer.OnClientDisconnect(Self);
        FServer.FClientStack.Push(Self);
      except
        _Release;
      end;
    end;  
    _Release;
  end;
end;

function THPServerClient.ReadBuffer(var Buffers: TWsaBuf; BufCount, CompletionKey: integer): integer;
var
  P: PHPSockIOStruct;
  BT, Flags: Cardinal;
begin
  _AddRef;
  P := ExchangeStruct(nil);
  if P = nil then P := Server.FStructStack.Pop;
  if P = nil then
  begin
    Result := ERROR_OUTOFMEMORY;
    _Release;
    Exit;
  end;
  FillChar(P.Ovp, SizeOf(P.Ovp), 0);
  P.CompletionKey := CompletionKey;
  P.OpCode := HPSO_READ;
  P.Client := Self;
  Flags := 0;
  Result := WSARecv(Handle, Buffers, BufCount, BT, Flags, POverlapped(P), nil);
  if Result = SOCKET_ERROR then
  begin
    Result := WSAGetLastError;
    if Result = WSA_IO_PENDING then begin
      Result := 0;
    end else begin
      P := ExchangeStruct(P);
      if P <> nil then FServer.FStructStack.Push(P);
      if Result <> WSAEWOULDBLOCK then Disconnect;
    end;
  end else begin
    Result := 0;
  end;
  if Result <> 0 then _Release;  
end;

function THPServerClient.WriteBuffer(var Buffers: TWsaBuf; BufCount, CompletionKey: integer): integer;
var
  P: PHPSockIOStruct;
  BT: Cardinal;
begin
  _AddRef;
  P := ExchangeStruct(nil);
  if P = nil then P := Server.FStructStack.Pop;
  if P = nil then
  begin
    Result := ERROR_OUTOFMEMORY;
    _Release;
    Exit;
  end;
  FillChar(P.Ovp, SizeOf(P.Ovp), 0);
  P.CompletionKey := CompletionKey;
  P.OpCode := HPSO_WRITE;
  P.Client := Self;
  Result := WSASend(Handle, Buffers, BufCount, BT, 0, POverlapped(P), nil);
  if Result = SOCKET_ERROR then
  begin
    Result := WSAGetLastError;
    if Result = WSA_IO_PENDING then begin
      Result := 0;
    end else begin
      P := ExchangeStruct(P);
      if P <> nil then FServer.FStructStack.Push(P);
      if Result <> WSAEWOULDBLOCK then Disconnect;
    end;
  end else begin
    Result := 0;
  end;
  if Result <> 0 then _Release;
end;

function THPServerClient.Transmit(hFile: THandle; BytesToWrite, BytesPerSend: DWORD;
                                  pTransmitBuffers: PTransmitFileBuffers;
                                  CompletionKey: integer; DisconnectClient: boolean): integer;
var
  P: PHPSockIOStruct;
  Flag: Cardinal;
begin
  _AddRef;
  if not Assigned(Server.FTransmitFile) then
  begin
    Result := -1;
    _Release;
    Exit;
  end;

  if DisconnectClient then begin
    if not LongBool(InterlockedExchange(integer(FConnected), integer(LongBool(false)))) then
    begin
      _Release;
      Result := WSAENOTCONN;
      Exit;
    end;
  end;  

  P := ExchangeStruct(nil);
  if P = nil then P := Server.FStructStack.Pop;
  if P = nil then
  begin
    InterlockedExchange(integer(FConnected), integer(LongBool(true)));
    Result := ERROR_OUTOFMEMORY;
    _Release;
    Exit;
  end;
  FillChar(P.Ovp, SizeOf(P.Ovp), 0);
  P.CompletionKey := CompletionKey;
  P.Client := Self;
  if DisconnectClient then
  begin
    P.OpCode := HPSO_TRANSMIT_DISCONNECT;
    Flag := TF_USE_KERNEL_APC or TF_DISCONNECT or TF_REUSE_SOCKET;
  end else
  begin
    P.OpCode := HPSO_TRANSMITFILE;
    Flag := TF_USE_KERNEL_APC;
  end;

  if not Server.FTransmitFile(Handle, hFile, BytesToWrite, BytesPerSend, @P.Ovp, pTransmitBuffers, Flag) then
  begin
    Result := WSAGetLastError;
    if Result = WSA_IO_PENDING then begin
      Result := 0;
    end else begin
      ExchangeStruct(P);
      InterlockedExchange(integer(FConnected), integer(LongBool(true)));
      if Result <> WSAEWOULDBLOCK then Disconnect;
    end;
  end else begin
    Result := 0;
  end;
  if Result <> 0 then _Release;
end;

{ THPServerSocket }

procedure THPServerSocket.AddWorkThread;
begin
  with FThreadsList.LockList do
  try
    Add(THPServerWorkThread.Create(Self, false));
  finally
    FThreadsList.UnlockList;
  end;
end;

function THPServerSocket.BindUserDevice(hDevice: THandle; CompletionKey: TUserKeyRange): boolean;
begin
  if not FActive then
  begin
    SetLastError(ERROR_NOT_READY);
    Result := false;
    exit;
  end;

  if (CompletionKey >= Low(TUserKeyRange)) and (CompletionKey <= High(TUserKeyRange)) then begin
    Result := FPort.AddDevice(hDevice, CompletionKey);
  end else begin
    SetLastError(ERROR_INVALID_PARAMETER);
    Result := false;
  end;
end;

procedure THPServerSocket.Close(Timeout: Cardinal);
var
  StartTime, TimeVal: int64;
  CThreads, n: integer;
  T: THPServerWorkThread;
  Client: TCustomHPServerClient;

  function GetNextTimeout: Cardinal;
  begin
    if Timeout <> INFINITE then
    begin
      TimeVal := GetTickCount;
      if TimeVal < StartTime then TimeVal := TimeVal + MAXDWORD + 1;
      TimeVal := TimeVal - StartTime;
      if TimeVal < Timeout then Result := cardinal(Timeout - TimeVal) else Result := 0;
    end else begin
      Result := INFINITE;
    end;  
  end;

begin
  if not longBool(InterlockedExchange(integer(FActive), integer(LongBool(false)))) then Exit;

  FClientStack.Closed := true;
  FStructStack.Closed := true;

  StartTime := GetTickCount;
  closesocket(InterlockedExchange(FListener, 0));
  FAcceptThread.Terminate;

  FConnections.Enum(CloseConnectionsProc);
  WaitForSingleObject(FClientsEvent, GetNextTimeout);

  if not FAcceptThread.WaitForTimeout(GetNextTimeout) then TerminateThread(FAcceptThread.Handle, 1);
  FreeAndNil(FAcceptThread);

  with FThreadsList.LockList do begin
    try
      CThreads := Count;
    finally
      FThreadsList.UnlockList;
    end;
  end;
  for n := 0 to Pred(CThreads) do begin
    FPort.SetCompletion(0, CP_TERMINATE, nil);
  end;

  repeat
    with FThreadsList.LockList do begin
      try
        if Count > 0 then
        begin
          T := THPServerWorkThread(Items[Count - 1]);
          Count := Count - 1;
        end else
          T := nil;
      finally
        FThreadsList.UnlockList;
      end;
    end;
    if T = nil then Break;
    if not T.WaitForTimeout(GetNextTimeout) then TerminateThread(T.Handle, 1);
    T.Free;
  until false;

  FStructStack.Clear;
  repeat
    Client := FConnections.Pop;
    if not Assigned(Client) then Break;
    Client.Free;
  until false;

  WSACleanup;
end;

function THPServerSocket.CloseConnectionsProc(AClient: TCustomHPServerClient): boolean;
begin
  Result := true;
  AClient.Disconnect;
end;

constructor THPServerSocket.Create{$IFDEF WITH_GUI}(AOwner: TComponent){$ENDIF};
begin
  inherited;
  FStructStack := TStructStack.Create(DefStuctStackCapacity, SizeOf(THPSockIOStruct));
  FPort := TCompletionPort.Create();
  FThreadsList := THPThreadList.Create;
  FDecreaseCompleteEvent := CreateEvent(nil, false, false, nil);
end;

function THPServerSocket.DecreaseWorkThreads: boolean;
var
  MinThr, SaveThreads: integer;
begin
  Result := 0 = InterlockedExchange(FDecreaseLock, 1);
  if not Result then Exit;
  
  try
    if FMinWorkThreads > 0
      then MinThr := FMinWorkThreads
      else MinThr := DefThreadsPerProcessor * FPort.ProcessorsCount;
    
    Result := FWorkThreads > MinThr;
    if Result then
    begin
{### 1.4.0.6 Changed June, 30, 2009}
      FDecreaseTryCount := FWorkThreads;
      SaveThreads := FWorkThreads;
      FPort.SetCompletion(0, CP_DELETETHREAD, nil);
      WaitForSingleObject(FDecreaseCompleteEvent, 100);
      Result := FWorkThreads < SaveThreads;
{### /1.4.0.6}
    end;
  finally
    InterlockedExchange(FDecreaseLock, 0);
  end;
end;

destructor THPServerSocket.Destroy;
begin
  inherited;
  if 0 <> FDecreaseCompleteEvent then CloseHandle(FDecreaseCompleteEvent);
  FPort.Free;
  FStructStack.Free;
  FThreadsList.Free;
end;

procedure THPServerSocket.Open;
var
  n, Min: integer;
begin
  if longBool(InterlockedExchange(integer(FActive), integer(LongBool(true)))) then Exit;
  try
    inherited;
    if not FPort.AddDevice(THandle(FListener), CP_IO)
      then raise EHPServerException.Create(SysErrorMessage(GetLastError));

    if FMinWorkThreads > 0
      then Min := FMinWorkThreads
      else Min := DefThreadsPerProcessor * FPort.ProcessorsCount;
    for n := 0 to Pred(Min) do AddWorkThread;
    FAcceptThread := TAcceptThread.Create(Self, false);
    AcceptorPriority := FAcceptorPriority;
  except
    with FThreadsList.LockList do begin
      try
        Min := Count;
      finally
        FThreadsList.UnlockList;
      end;
    end;
    for n := 0 to Pred(Min) do FPort.SetCompletion(0, CP_TERMINATE, nil);
    if FListener <> 0 then closesocket(FListener);
    FListener := 0;
    InterlockedExchange(integer(FActive), integer(LongBool(false)));
    raise;
  end;
end;

procedure THPServerSocket.SetClientClass(const Value: THPServerClientClass);
begin
  if not FActive then
  begin
    if Value = nil then begin
      FClientClass := THPServerClient;
    end else 
    if Value.InheritsFrom(THPServerClient) then begin
      FClientClass := Value;
    end else begin
      raise EHPServerException.Create(sClassInvalid);
    end;  
  end;
end;

procedure THPServerSocket.SetMinWorkThreads(const Value: integer);
begin
  if Value >= 0 then InterlockedExchange(FMinWorkThreads, Value);
end;

procedure THPServerSocket.SetOnAcceptorEnd(const Value: TNotifyEvent);
begin
  if not FActive then FOnAcceptorEnd := Value;
end;

procedure THPServerSocket.SetOnAcceptorStart(const Value: TNotifyEvent);
begin
  if not FActive then FOnAcceptorStart := Value;
end;

procedure THPServerSocket.SetOnDeviceCompletion(const Value: THPUserDeviceEvent);
begin
  if not FActive then FOnDeviceCompletion := Value;
end;

procedure THPServerSocket.SetOnThreadEnd(const Value: TNotifyEvent);
begin
  if not FActive then FOnThreadEnd := Value;
end;

procedure THPServerSocket.SetOnThreadStart(const Value: TNotifyEvent);
begin
  if not FActive then FOnThreadStart := Value;
end;

procedure THPServerSocket.SetOnUserAsyncCall(const Value: THPServUserAsyncCall);
begin
  if not FActive then FOnUserAsyncCall := Value;
end;

function THPServerSocket.UserAsyncCall(UserKey: Cardinal; PUserData: Pointer): boolean;
begin
  if FActive then
    Result := FPort.SetCompletion(UserKey, CP_USERASYNCCALL, PUserData)
  else
    Result := false;
end;

{ THPServerWorkThread }

constructor THPServerWorkThread.Create(Server: THPServerSocket; CreateSyspended: boolean);
begin
  FServer := Server;
  inherited Create(CreateSyspended);
end;

procedure THPServerWorkThread.Execute;
var
  POvp: POverlapped;
  PStruct: PHPSockIOStruct absolute POvp;
  P: Pointer;
  C: THPServerClient;
  BytesTransfered, CP: Cardinal;
  WaitRslt, DecreaseFlag: boolean;
  Key, ErrorCode: integer;
  s: TSocket;
begin
  InterlockedIncrement(FServer.FWorkThreads);
  DecreaseFlag := false;
  if Assigned(FServer.FOnThreadStart) then FServer.OnThreadStart(FServer);

  try
    repeat
      CP := CP_TERMINATE;  DecreaseFlag := false;
      WaitRslt := FServer.FPort.WaitCompletion(BytesTransfered, CP, POvp);
      InterlockedIncrement(FServer.FActiveThreads);

      try
        case CP of
          CP_TERMINATE: Break;
          CP_IO:;

{### 1.4.0.6 Changed June, 30, 2009}
          CP_DELETETHREAD:
          begin
            DecreaseFlag := true;
            if WaitRslt then
            begin
              if ThreadIsIoPending(Handle) then
              begin
                if InterlockedDecrement(FServer.FDecreaseTryCount) > 0 then
                begin
                  FServer.FPort.SetCompletion(0, CP_DELETETHREAD, nil);
                  Sleep(10);
                end else
                  SetEvent(FServer.FDecreaseCompleteEvent);
              end else
                Break;
            end else
              Break;
          end;
{### /1.4.0.6}

          CP_USERASYNCCALL:
          begin
            if WaitRslt then
            begin
              if Assigned(FServer.OnUserAsyncCall) then begin
                try
                  FServer.OnUserAsyncCall(FServer, BytesTransfered, POvp);
                except
                  on E: Exception do if Assigned(FServer.OnThreadException) then
                    FServer.OnThreadException(nil, E.Message, E.ClassName, ExceptAddr);
                end;
              end;
              Continue;
            end else
              Break;
          end;

          Low(TUserKeyRange)..High(TUserKeyRange):
          begin
            if Assigned(FServer.OnUserDeviceCompletion) then begin
              try
                FServer.OnUserDeviceCompletion(FServer, WaitRslt,
                  BytesTransfered, CP, POvp);
              except
                on E: Exception do if Assigned(FServer.OnThreadException) then
                  FServer.OnThreadException(nil, E.Message, E.ClassName, ExceptAddr);
              end;    
            end;      
          end;

          else Break;
        end;


        if pOvp = nil then Break;
        if WaitRslt then ErrorCode := 0 else Cardinal(ErrorCode) := GetLastError;

        C := PStruct.Client;
        try
          try
            case PStruct.OpCode of

              HPSO_ACCEPT:
              begin
                FServer.ClientAccepted;
                if not FServer.Active or (ErrorCode <> ERROR_SUCCESS) then
                begin
                  s := C.ExtractSocket;
                  closesocket(s);
                  FServer.FClientStack.Push(C);
                  FServer.FStructStack.Push(PStruct);
                end else
                begin
                  C.FConnected := true;
                  FServer.FConnections.Push(C);
                  C.ExtractAddresses;
                  P := C.ExchangeStruct(PStruct);
                  if P <> nil then FServer.FStructStack.Push(P);
                  if Assigned(FServer.OnClientConnect) then
                  try
                    FServer.OnClientConnect(C, C.FpConnectBuf, integer(BytesTransfered));
                  except
                    C.Disconnect;
                  end;
                end;
              end; // HPSO_ACCEPT

              HPSO_READ:
              begin
                Key := PStruct.CompletionKey;
                P := C.ExchangeStruct(PStruct);
                if P <> nil then FServer.FStructStack.Push(P);
                if Assigned(FServer.OnReadComplete) then begin
                  try
                    FServer.OnReadComplete(C, BytesTransfered, Key, ErrorCode);
                  except
                    C.Disconnect;
                  end;
                end;

                if WaitRslt then
                begin
                  if BytesTransfered = 0 then C.Disconnect;
                end else
                  if ErrorCode <> WSAEWOULDBLOCK then C.Disconnect;
              end; // HPSO_READ

              HPSO_WRITE,
              HPSO_TRANSMITFILE:
              begin
                Key := PStruct.CompletionKey;
                P := C.ExchangeStruct(PStruct);
                if P <> nil then FServer.FStructStack.Push(P);
                if Assigned(FServer.OnWriteComplete) then begin
                  try
                    FServer.OnWriteComplete(C, BytesTransfered, Key, ErrorCode);
                  except
                    C.Disconnect;
                  end;
                end;  

                if WaitRslt then
                begin
                  if BytesTransfered = 0 then C.Disconnect;
                end else
                  if ErrorCode <> WSAEWOULDBLOCK then C.Disconnect;
              end; // HPSO_WRITE

              HPSO_TRANSMIT_DISCONNECT:
              begin
                FServer.FConnections.Remove(C);
                Key := PStruct.CompletionKey;
                P := C.ExchangeStruct(nil);
                if P <> nil then FServer.FStructStack.Push(P);
                FServer.FStructStack.Push(PStruct);
                if Assigned(FServer.OnWriteComplete) then begin
                  try
                    FServer.OnWriteComplete(C, BytesTransfered, Key, ErrorCode);
                  except
                    // do nothing
                  end;
                end;  

                if (WaitRslt) or (ErrorCode <> WSAEWOULDBLOCK) then
                begin
                  if WaitRslt then s := 0 else s := C.ExtractSocket;
                  if Assigned(FServer.OnClientDisconnect) then begin
                    try
                      FServer.OnClientDisconnect(C);
                      FServer.FClientStack.Push(C);
                    except
                      C._Release;
                    end;
                  end else begin
                    FServer.FClientStack.Push(C);
                  end;  

                  if s <> 0 then closesocket(s);
                end;
              end; // HRSO_TRANSMIT_DISCONNECT

              HPSO_DISCONNECT:
              begin
                FServer.FConnections.Remove(C);
                P := C.ExchangeStruct(nil);
                if P <> nil then FServer.FStructStack.Push(P);
                FServer.FStructStack.Push(PStruct);
                if Assigned(FServer.OnClientDisconnect) then begin
                  try
                    FServer.OnClientDisconnect(C);
                    FServer.FClientStack.Push(C);
                  except
                    C._Release;
                  end;
                end else begin
                  FServer.FClientStack.Push(C);
                end;  

              end; // HPSO_DISCONNECT

            end; // case PStruct.OpCode

          finally
            C._Release;
          end;
        except
          on E: Exception do
            if Assigned(FServer.OnThreadException) then
              FServer.OnThreadException(C, E.Message, E.ClassName, ExceptAddr);
        end;

      finally
        InterlockedDecrement(FServer.FActiveThreads);
      end;
    until false;

  finally
    FreeOnTerminate := FServer.FThreadsList.Remove(Self);
    InterlockedDecrement(FServer.FWorkThreads);
    if DecreaseFlag then SetEvent(FServer.FDecreaseCompleteEvent);
    if Assigned(FServer.OnThreadEnd) then FServer.OnThreadEnd(FServer);
  end;
end;

function THPServerWorkThread.WaitForTimeout(TimeOut: cardinal): boolean;
begin
  Result := WaitForSingleObject(Handle, TimeOut) = WAIT_OBJECT_0;
end;

{$IFNDEF MINWINXP}
{$IFDEF USE_SLIST}
initialization
  InitSListFunc(SListFunc);
{$ENDIF}
{$ENDIF}

end.
