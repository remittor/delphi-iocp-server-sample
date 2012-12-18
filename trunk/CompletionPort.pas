unit CompletionPort;

{*******************************************************************************
TCompletionPort: Класс - обертка для windows completion port

Created:            ?
Last modification:  23.08.2008

To do: Not

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

TMultiReadSingleWrite - примитив синхронизации, обеспечивает доступ множества
  потоков на чтение, но только одного - на запись.

Created:            31.08.2008
Last modified:      -

To do: No

********************************************************************************
Author: Sergey N. Naberegnyh ( Набережных С.Н. )
*******************************************************************************}

{$I CompVersionDef.inc}

interface

uses
  Windows;

type
  POverlappedEx = ^TOverlappedEx;
  TOverlappedEx = record
    Ovp: TOverlapped;
    Obj: Pointer;
  end;

  TCompletionPort = class
  private
    FMaxActiveThreads: Cardinal;
    FHandle: THandle;
    class function GetProcessorsCount(): integer;
  public
    constructor Create(MaxActiveThreads: Cardinal = 0);
    destructor Destroy;override;

    function AddDevice(hDevice: THandle; CompletionKey: Cardinal): boolean;
    function FreeDevice(hDevice: THandle): boolean;
    function WaitCompletion(out NumBytes, CompKey: Cardinal;
               out pOvp: POverlapped; TimeOut: Cardinal = INFINITE): boolean;
    function SetCompletion(NumBytes, CompKey: Cardinal;
      pOvp: POverlapped): boolean;

    property ProcessorsCount: integer read GetProcessorsCount;
    property Handle: THandle read FHandle;
    property MaxActiveThreads: Cardinal read FMaxActiveThreads;
  end;

  TMultiReadSingleWrite = class(TObject)
  private
    FSyncMutex: THandle;
    FReadEvent, FWriteEvent: THandle;
    FReadLockCount,
    FWaitReadCount,
    FWriteLockCount: integer;
    FSpinCount: integer;
    procedure CaptureMutex();
    procedure SetSpinCount(Value: integer);
  public
    constructor Create(ASpinCount: integer = 32);
    destructor Destroy(); override;
    
    procedure ReadLock;
    procedure ReadUnlock;
    procedure WriteLock;
    procedure WriteUnlock;

    property SpinCount: integer read FSpinCount write SetSpinCount;
  end;

implementation

uses
  SysUtils;

var
  CountOfProcessors: integer = 0;

function _ProcessorsCount: integer;
var
  Info: TSystemInfo;
begin
  GetSystemInfo(Info);
  Result:= integer(Info.dwNumberOfProcessors);
end;

{ TCompletionPort }

constructor TCompletionPort.Create(MaxActiveThreads: Cardinal);
begin
  FMaxActiveThreads:= MaxActiveThreads;
  FHandle:= CreateIoCompletionPort(INVALID_HANDLE_VALUE,
              0 , 0, FMaxActiveThreads);
  if FHandle = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}
end;

function TCompletionPort.AddDevice(hDevice: THandle;
  CompletionKey: Cardinal): boolean;
begin
  Result:= CreateIoCompletionPort(hDevice, Handle, CompletionKey, 0) = FHandle;
end;

destructor TCompletionPort.Destroy;
begin
  if FHandle <> 0 then CloseHandle(FHandle);
  inherited;
end;

function TCompletionPort.FreeDevice(hDevice: THandle): boolean;
begin
  Result:= CloseHandle(hDevice);
end;

function TCompletionPort.SetCompletion(NumBytes, CompKey: Cardinal;
  pOvp: POverlapped): boolean;
begin
  Result:= PostQueuedCompletionStatus(Handle, NumBytes, CompKey, pOvp);
end;

function TCompletionPort.WaitCompletion(out NumBytes, CompKey: Cardinal;
  out pOvp: POverlapped; TimeOut: Cardinal = INFINITE): boolean;
begin
  Result:= GetQueuedCompletionStatus(Handle, NumBytes, CompKey, pOvp, TimeOut);
end;

class function TCompletionPort.GetProcessorsCount: integer;
begin
  if CountOfProcessors = 0 then
    CountOfProcessors:= _ProcessorsCount;
  Result:= CountOfProcessors;
end;

{ TMultiReadSingleWrite }

procedure TMultiReadSingleWrite.CaptureMutex;
var
  n, SC: integer;
begin
  SC:= FSpinCount;
  if (CountOfProcessors > 1) and (SC > 0) then
  begin
    for n:= 0 to Pred(SC) do
      if WaitForSingleObject(FSyncMutex, 0) = WAIT_OBJECT_0 then Exit;
  end;
  WaitForSingleObject(FSyncMutex, INFINITE);
end;

constructor TMultiReadSingleWrite.Create(ASpinCount: integer);
var
  SA: TSecurityAttributes;
  SD: TSecurityDescriptor;
begin
  if ASpinCount > 0 then FSpinCount:= ASpinCount;
  if CountOfProcessors = 0 then CountOfProcessors := _ProcessorsCount;

  InitializeSecurityDescriptor(@SD, SECURITY_DESCRIPTOR_REVISION);
  SetSecurityDescriptorDacl(@SD, true, nil, false);
  SA.nLength:= SizeOf(SA);
  SA.lpSecurityDescriptor:= @SD;
  SA.bInheritHandle:= false;

  FSyncMutex:= CreateMutex(@SD, false, nil);
  if FSyncMutex = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}

  FReadEvent:= CreateEvent(@SD, true, false, nil);
  if FReadEvent = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}

  FWriteEvent:= CreateEvent(@SD, false, false, nil);
  if FWriteEvent = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}
end;

destructor TMultiReadSingleWrite.Destroy;
begin
  if 0 <> FWriteEvent then CloseHandle(FWriteEvent);
  if 0 <> FReadEvent then CloseHandle(FReadEvent);
  if 0 <> FSyncMutex then CloseHandle(FSyncMutex); 
  inherited;
end;

procedure TMultiReadSingleWrite.ReadLock;
begin
  CaptureMutex;
  if FWriteLockCount = 0 then
  begin
    Inc(FReadLockCount);
    ReleaseMutex(FSyncMutex);
  end else
  begin
    Inc(FWaitReadCount);
    SignalObjectAndWait(FSyncMutex, FReadEvent, INFINITE, false);
  end;
end;

procedure TMultiReadSingleWrite.ReadUnlock;
begin
  CaptureMutex;
  Dec(FReadLockCount);
  if (0 = FReadLockCount) and (0 < FWriteLockCount)
  then SetEvent(FWriteEvent);
  ReleaseMutex(FSyncMutex);
end;

procedure TMultiReadSingleWrite.SetSpinCount(Value: integer);
begin
  if Value < 0 then Value:= 0;
  InterlockedExchange(FSpinCount, Value);
end;

procedure TMultiReadSingleWrite.WriteLock;
begin
  CaptureMutex;
  Inc(FWriteLockCount);
  ResetEvent(FReadEvent);
  if (0 = FReadLockCount) and (1 = FWriteLockCount)
  then ReleaseMutex(FSyncMutex)
  else SignalObjectAndWait(FSyncMutex, FWriteEvent, INFINITE, false);
end;

procedure TMultiReadSingleWrite.WriteUnlock;
begin
  CaptureMutex;
  Dec(FWriteLockCount);
  if 0 = FWriteLockCount then
  begin
    Inc(FReadLockCount, FWaitReadCount);
    FWaitReadCount:= 0;
    SetEvent(FReadEvent);
  end else
    SetEvent(FWriteEvent);
  ReleaseMutex(FSyncMutex);
end;

end.

