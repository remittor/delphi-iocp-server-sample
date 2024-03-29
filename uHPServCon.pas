unit uHPServCon;

{$WARN UNIT_PLATFORM OFF}

interface

uses
  Windows, Messages, SysUtils, Classes,
  HPSockApi, HPScktSrvr, WinSock, uTempLog;

type
  TGarbageThread = class(TThread)
  private
    FServer: THPServerSocket;
    FTerminateEvent: THandle;
    function EnumClients(ACient: TCustomHPServerClient): boolean;
  protected
    procedure Execute; override;
  public
    constructor Create(AServer: THPServerSocket);
    destructor Destroy; override;
    procedure Terminate;
  end;

  THPServerCon = class
    HPServerSocket: THPServerSocket;
    LogBuffer: TTempLogBuffer;
    function ServerOpen(const Port: String): Boolean;
    function ServerClose: Boolean;
    procedure HPSrvClientBeforeAccept(AClient: TCustomHPServerClient; var ConnBufSize: Integer);
    procedure HPSrvClientConnect(AClient: TCustomHPServerClient; ConnectionData: PChar; ConnectionDataLen: Integer);
    procedure HPSrvClientDisconnect(AClient: TCustomHPServerClient);
    procedure HPSrvClientFinalizeRef1(AClient: TCustomHPServerClient);
    procedure HPSrvReadComplete(AClient: TCustomHPServerClient; BytesTransfered: Cardinal; CompletionKey, Error: Integer);
    procedure HPSrvWriteComplete(AClient: TCustomHPServerClient; BytesTransfered: Cardinal; CompletionKey, Error: Integer);
    procedure HPSrvExceptionEvent(AClient: TCustomHPServerClient; const Message: String; const ExceptClass: String; ExceptAddress: Pointer);
    procedure HPSrvThreadStart;
    procedure HPSrvThreadEnd;
  private
    { Private declarations }
    ExeDir: String;
    ExePath: String;
    FGarbageThread: TGarbageThread;
    procedure ServerLogMsg(ModuleID, LogLevel: Byte; ThreadID, ClientID: Cardinal; const Line: String);
    procedure SrvLogMsg(ModuleID, LogLevel: Byte; ClientID: Cardinal; const Line: String);
  public
    { Public declarations }
    constructor Create(const AExeDir: String); 
    destructor Destroy; override;
  end;

var
  HPSrv: THPServerCon;
  RootDir: String = 'WWW';
  HPServerPort: Integer = 5000;

const
  sSend_OK = 'HTTP/1.0 200 OK'#$0D#$0A'Server: HttpDemo 2.0'#$0D#$0A +
    'Content-length: %d'#$0D#$0A#$0D#$0A;
  sSend_OK_KeepAlive = 'HTTP/1.0 200 OK'#$0D#$0A'Server: HttpDemo 2.0'#$0D#$0A +
    'Connection: Keep-Alive'#$0D#$0A +
    'Content-length: %d'#$0D#$0A#$0D#$0A;

  MAX_LINE_LEN = 1000;
  WSATYPE_NOT_FOUND = 10109;

implementation

uses
  uHPServClient;

{ THPServerCon }

// ����� �������� ����� ��������� ���� �� ���� N ���������� �������� ������ ��� ���������� ������ Connected
// ��. ��������� WaitConnectionData
// ����� ������� ������ ������ ��� ��� � ������ ������ ������, � ������� �������� ������� AcceptEx
procedure THPServerCon.HPSrvClientBeforeAccept(AClient: TCustomHPServerClient; var ConnBufSize: Integer);
begin
  ConnBufSize := $10000 - 2 * Addr_Buf_Len;
end;

function THPServerCon.ServerOpen(const Port: String): Boolean;
var
  Protocols: Cardinal;
  w: integer;
begin
  Result := False;
  GlobClientIDs := 0;
  if not DirectoryExists(ExePath+RootDir) then begin
    Writeln('Error: Directory "'+RootDir+'" not found !!!');
    Exit;
  end;
  HPServerSocket.Address := '';   // 0.0.0.0
  HPServerSocket.Port := Port;
  HPServerSocket.OnLogMsg := ServerLogMsg;
  HPServerSocket.ClientClass := THttpSrvClient;

  FGarbageThread := TGarbageThread.Create(HPServerSocket);

  try
    HPServerSocket.Open;
    Result := True;
    HPServerSocket.LogMsgXT(1, 1, 'HPServerSocket Start !!!');
    OutputDebugString(PChar(ODSPrefix1+'HPServerSocket Start !!!'));
  except
    on E: Exception do begin
      if Assigned(FGarbageThread) then begin
        FGarbageThread.Terminate;
        FreeAndNil(FGarbageThread);
      end;
      if E is ESockAddrError then begin
        if (ESockAddrError(E).ErrCode = WSATYPE_NOT_FOUND) or (ESockAddrError(E).ErrCode = WSANO_DATA) then begin
          //Writeln('Error: Unknown service name!');
          HPServerSocket.LogMsgXS(1, 0, '[ERROR] ServerOpen: Unknown service');
        end else begin
          //Writeln('Error: '+E.Message);
          HPServerSocket.LogMsgXS(1, 0, '[ERROR] ServerOpen: Error: '+E.Message);
        end;
        Exit;
      end else begin
        raise;
      end;
    end;
  end;
end;

function THPServerCon.ServerClose: Boolean;
begin
  if Assigned(FGarbageThread) then begin
    FGarbageThread.Terminate;
    FreeAndNil(FGarbageThread);
  end;
  HPServerSocket.Close(INFINITE);   //HPServerSocket.Close(3000);
  HPServerSocket.LogMsgXT(1, 1, 'HPServerSocket Close !!!');
  OutputDebugString(PChar(ODSPrefix1+'HPServerSocket Close !!!'));  // DO-
end;

procedure THPServerCon.HPSrvClientConnect(AClient: TCustomHPServerClient; ConnectionData: PChar; ConnectionDataLen: Integer);
var
  CID: Integer;
  s: String;
begin
  CID := THttpSrvClient(AClient).ClientID;
  HPServerSocket.LogMsgXTC(1, 1, CID, 'Connect     IP='+THttpSrvClient(AClient).RemoteAddress);
  with THttpSrvClient(AClient) do begin
    Initialize;
    ProcessBuffer(ConnectionData, ConnectionDataLen);
  end;
end;

procedure THPServerCon.HPSrvClientDisconnect(AClient: TCustomHPServerClient);
var
  CID: Integer;
begin
  CID := THttpSrvClient(AClient).ClientID;
  HPServerSocket.LogMsgXTC(1, 1, CID, 'Disconnect  IP='+THttpSrvClient(AClient).RemoteAddress);
  THttpSrvClient(AClient).Finalize;
end;

procedure THPServerCon.HPSrvClientFinalizeRef1(AClient: TCustomHPServerClient);
begin
  //THttpSrvClient(AClient).FinalizeRef1;
end;

procedure THPServerCon.HPSrvReadComplete(AClient: TCustomHPServerClient; BytesTransfered: Cardinal; CompletionKey, Error: Integer);
var
  ActClient: THttpSrvClient absolute AClient;
begin
  if Error <> 0 then begin
    {$IFDEF EXTLOG}
    HPServerSocket.LogMsgXTC(1, 1, ActClient.ClientID, 'Error on ReadComplete: '+IntToStr(Error)+' (size='+IntToStr(BytesTransfered)+')');
    {$ENDIF}
    AClient.Disconnect;
  end else begin
    if BytesTransfered > 0 then begin  // ��� 0 ��� ����� ��� �������� ���������� !!!
      {$IFDEF EXTLOG}
      HPServerSocket.LogMsgXTC(1, 1, ActClient.ClientID, 'ReadComplete (size='+IntToStr(BytesTransfered)+') --> ProcessBuffer ...');
      {$ENDIF}
      ActClient.ProcessBuffer(ActClient.RecvBuf, Integer(BytesTransfered));
    end;
  end;
end;

procedure THPServerCon.HPSrvWriteComplete(AClient: TCustomHPServerClient; BytesTransfered: Cardinal; CompletionKey, Error: Integer);
var
  CID: Integer;
begin
  CID := THttpSrvClient(AClient).ClientID;
  if Error <> 0 then begin
    {$IFDEF EXTLOG}
    HPServerSocket.LogMsgXTC(1, 1, CID, 'Error on WriteComplete: '+IntToStr(Error)+' (size='+IntToStr(BytesTransfered)+')');
    {$ENDIF}
    AClient.Disconnect($62);
  end else begin
    {$IFDEF EXTLOG}
    HPServerSocket.LogMsgXTC(1, 1, CID, 'WriteComplete (size='+IntToStr(BytesTransfered)+') --> DoWriteComplete ...');
    {$ENDIF}
    THttpSrvClient(AClient).DoWriteComplete(BytesTransfered, CompletionKey, Error);
  end;
end;

procedure THPServerCon.HPSrvExceptionEvent(AClient: TCustomHPServerClient; const Message: String; const ExceptClass: String; ExceptAddress: Pointer);
var
  ActClient: THttpSrvClient absolute AClient;
begin
  try
    HPServerSocket.LogMsgXTC(3, 0, ActClient.ClientID, '[ERROR] '+ExceptClass+': '+Message+' (Addr '+IntToHex(Cardinal(ExceptAddress), 8)+')');
  except
  end;
end;

constructor THPServerCon.Create(const AExeDir: String);
begin
  ExeDir := AExeDir;
  ExePath := AExeDir + '\';
  LogBuffer := TTempLogBuffer.Create;
  LogBuffer.FDebugLog := True;
  LogBuffer.SetLogParams(1, True, True, ExePath+'logs', 'main_');
  LogBuffer.SetLogParamsODS(1, ODSPrefix1);
  LogBuffer.SetLogParamsODS(2, ODSPrefix2);
  LogBuffer.CreateThreadWriteLog;
  LogBuffer.StartThreadWriteLog;
  HPServerSocket := THPServerSocket.Create;
  LogBuffer.AddLine1S(1, 'HPServerSocket Create !!!');
  OutputDebugString(PChar(ODSPrefix1+'HPServerSocket Create !!!'));
end;

procedure THPServerCon.ServerLogMsg(ModuleID, LogLevel: Byte; ThreadID, ClientID: Cardinal; const Line: String);
begin
  LogBuffer.AddLine(ModuleID, LogLevel, ThreadID, ClientID, Line);
end;

procedure THPServerCon.SrvLogMsg(ModuleID, LogLevel: Byte; ClientID: Cardinal; const Line: String);
begin
  LogBuffer.AddLine(ModuleID, LogLevel, $FFFFFFFF, ClientID, Line);
end;

destructor THPServerCon.Destroy; 
begin
  LogBuffer.AddLine1S(1, 'HPServerSocket Destroy !!!');
  HPServerSocket.Free;
  if LogBuffer.DestroyThreadWriteLog then LogBuffer.Free;
  OutputDebugString(PChar(ODSPrefix1+'HPServerSocket Destroy !!!'));
end;

procedure THPServerCon.HPSrvThreadStart;
begin
  //
end;

procedure THPServerCon.HPSrvThreadEnd;
begin
  //
end;

{ TGarbageThread }

constructor TGarbageThread.Create(AServer: THPServerSocket);
begin
  FTerminateEvent:= CreateEvent(nil, false, false, nil);
  FServer:= AServer;
  inherited Create(false);
end;

destructor TGarbageThread.Destroy;
begin
  CloseHandle(FTerminateEvent);
  inherited;
end;

function TGarbageThread.EnumClients(ACient: TCustomHPServerClient): boolean;
begin
  Result:= not Terminated;
  if not Result then Exit;
  if ACient.ConnectionTime > 10 then begin
    ACient.Disconnect;
  end;
end;

procedure TGarbageThread.Execute;
begin
  iCurrentThreadID := Self.ThreadID;
  repeat
    if WaitForSingleObject(FTerminateEvent, 60000) = WAIT_TIMEOUT then begin
      FServer.EnumerateConnections(EnumClients);
    end else begin
      Break;
    end;
  until Terminated;
end;

procedure TGarbageThread.Terminate;
begin
  inherited;
  SetEvent(FTerminateEvent);
end;

end.

