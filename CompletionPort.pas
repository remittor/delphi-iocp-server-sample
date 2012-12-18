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

{ ********************************************************************************
// Martin Harvey 27/5/2000
TSimpleSynchronizer - Multiple Read Exclisive Write Synchronizer

// Martin Harvey 5/6/2000
TEventSynchronizer - Multiple Read Exclisive Write Synchronizer

******************************************************************************** }

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
    function WaitCompletion(out NumBytes, CompKey: Cardinal; out pOvp: POverlapped; TimeOut: Cardinal = INFINITE): boolean;
    function SetCompletion(NumBytes, CompKey: Cardinal; pOvp: POverlapped): boolean;

    property ProcessorsCount: integer read GetProcessorsCount;
    property Handle: THandle read FHandle;
    property MaxActiveThreads: Cardinal read FMaxActiveThreads;
  end;

  TMultiReadSingleWrite = class(TObject)
  private
    FSecAttr: TSecurityAttributes;
    FSecDesc: TSecurityDescriptor;
    FSyncMutex: THandle;
    FReadEvent: THandle;
    FWriteEvent: THandle;
    FReadLockCount: Integer;
    FWaitReadCount: Integer;
    FWriteLockCount: Integer;
    FSpinCount: Integer;
    procedure CaptureMutex;
    procedure SetSpinCount(Value: Integer);
  public
    constructor Create(ASpinCount: Integer = 32);
    destructor Destroy; override;
    procedure ReadLock;
    procedure ReadUnlock;
    procedure WriteLock;
    procedure WriteUnlock;
    property SpinCount: Integer read FSpinCount write SetSpinCount;
  end;

  TSimpleSynchronizer = class(TObject)
  private
    FDataLock: TRTLCriticalSection;
    FWriteLock: TRTLCriticalSection;
    FActRead: Integer;
    FReadRead: Integer;
    FActWrite: Integer;
    FWriteWrite: Integer;
    FReaderSem: THandle;
    FWriterSem: THandle;
  public
    constructor Create;
    destructor Destroy; override;
    procedure StartRead;
    procedure StartWrite;
    procedure EndRead;
    procedure EndWrite;
  end;

  TEventSynchronizer = class(TObject)
  private
    FDataLock: TRTLCriticalSection;
    FWriteLock: TRTLCriticalSection;
    FReaders: Integer;
    FWriters: Integer;
    FNoReaders: THandle;
    FNoWriters: THandle;
  public
    constructor Create;
    destructor Destroy; override;
    procedure StartRead;
    procedure StartWrite;
    procedure EndRead;
    procedure EndWrite;
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
  FMaxActiveThreads := MaxActiveThreads;
  FHandle := CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, FMaxActiveThreads);
  if FHandle = 0 then {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}
end;

function TCompletionPort.AddDevice(hDevice: THandle; CompletionKey: Cardinal): boolean;
begin
  Result := CreateIoCompletionPort(hDevice, Handle, CompletionKey, 0) = FHandle;
end;

destructor TCompletionPort.Destroy;
begin
  if FHandle <> 0 then CloseHandle(FHandle);
  inherited;
end;

function TCompletionPort.FreeDevice(hDevice: THandle): boolean;
begin
  Result := CloseHandle(hDevice);
end;

function TCompletionPort.SetCompletion(NumBytes, CompKey: Cardinal; pOvp: POverlapped): boolean;
begin
  Result := PostQueuedCompletionStatus(Handle, NumBytes, CompKey, pOvp);
end;

function TCompletionPort.WaitCompletion(out NumBytes, CompKey: Cardinal; out pOvp: POverlapped; TimeOut: Cardinal = INFINITE): boolean;
begin
  Result := GetQueuedCompletionStatus(Handle, NumBytes, CompKey, pOvp, TimeOut);
end;

class function TCompletionPort.GetProcessorsCount: integer;
begin
  if CountOfProcessors = 0 then CountOfProcessors := _ProcessorsCount;
  Result := CountOfProcessors;
end;

{ TMultiReadSingleWrite }

procedure TMultiReadSingleWrite.CaptureMutex;
var
  n, SC: integer;
begin
  SC := FSpinCount;
  if (CountOfProcessors > 1) and (SC > 0) then begin
    for n:=0 to Pred(SC) do begin
      if WaitForSingleObject(FSyncMutex, 0) = WAIT_OBJECT_0 then Exit;
    end;  
  end;
  WaitForSingleObject(FSyncMutex, INFINITE);
end;

constructor TMultiReadSingleWrite.Create(ASpinCount: Integer = 32);
begin
  if ASpinCount > 0 then FSpinCount := ASpinCount;
  if CountOfProcessors = 0 then CountOfProcessors := _ProcessorsCount;

  if not InitializeSecurityDescriptor(@FSecDesc, SECURITY_DESCRIPTOR_REVISION) then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}
  if not SetSecurityDescriptorDacl(@FSecDesc, True, nil, False) then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}
  FSecAttr.nLength := SizeOf(FSecAttr);
  FSecAttr.lpSecurityDescriptor := @FSecDesc;
  FSecAttr.bInheritHandle := False;

  FSyncMutex := CreateMutex(@FSecAttr, False, nil);
  if FSyncMutex = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}

  FReadEvent := CreateEvent(@FSecAttr, True, False, nil);
  if FReadEvent = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}

  FWriteEvent := CreateEvent(@FSecAttr, False, False, nil);
  if FWriteEvent = 0 then
    {$IFDEF VER140__}RaiseLastOsError;{$ELSE}RaiseLastWin32Error;{$ENDIF}
end;

destructor TMultiReadSingleWrite.Destroy;
begin
  if FWriteEvent <> 0 then CloseHandle(FWriteEvent);
  if FReadEvent  <> 0 then CloseHandle(FReadEvent);
  if FSyncMutex  <> 0 then CloseHandle(FSyncMutex); 
  inherited;
end;

procedure TMultiReadSingleWrite.ReadLock;
begin
  CaptureMutex;
  if FWriteLockCount = 0 then begin
    Inc(FReadLockCount);
    ReleaseMutex(FSyncMutex);
  end else begin
    Inc(FWaitReadCount);
    SignalObjectAndWait(FSyncMutex, FReadEvent, INFINITE, false);
  end;
end;

procedure TMultiReadSingleWrite.ReadUnlock;
begin
  CaptureMutex;
  Dec(FReadLockCount);
  if (FReadLockCount = 0) and (FWriteLockCount > 0) then SetEvent(FWriteEvent);
  ReleaseMutex(FSyncMutex);
end;

procedure TMultiReadSingleWrite.SetSpinCount(Value: integer);
begin
  if Value < 0 then Value := 0;
  InterlockedExchange(FSpinCount, Value);     // FSpinCount := Value
end;

procedure TMultiReadSingleWrite.WriteLock;
begin
  CaptureMutex;
  Inc(FWriteLockCount);
  ResetEvent(FReadEvent);
  if (FReadLockCount = 0) and (FWriteLockCount = 1) then begin
    ReleaseMutex(FSyncMutex);
  end else begin
    SignalObjectAndWait(FSyncMutex, FWriteEvent, INFINITE, False);
  end;
end;

procedure TMultiReadSingleWrite.WriteUnlock;
begin
  CaptureMutex;
  Dec(FWriteLockCount);
  if FWriteLockCount = 0 then begin
    Inc(FReadLockCount, FWaitReadCount);
    FWaitReadCount := 0;
    SetEvent(FReadEvent);
  end else begin
    SetEvent(FWriteEvent);
  end;  
  ReleaseMutex(FSyncMutex);
end;

{  TSimpleSynchronizer  }

constructor TSimpleSynchronizer.Create;
begin
  inherited Create;
  InitializeCriticalSection(FDataLock);
  InitializeCriticalSection(FWriteLock);
  FReaderSem := CreateSemaphore(nil, 0, High(Integer), nil);
  FWriterSem := CreateSemaphore(nil, 0, High(Integer), nil);
  { Initial values of 0 OK for all counts }
end;

destructor TSimpleSynchronizer.Destroy;
begin
  DeleteCriticalSection(FDataLock);
  DeleteCriticalSection(FWriteLock);
  CloseHandle(FReaderSem);
  CloseHandle(FWriterSem);
  inherited Destroy;
end;

procedure TSimpleSynchronizer.StartRead;
begin
  EnterCriticalSection(FDataLock);
  Inc(FActRead);
  if FActWrite = 0 then begin
    Inc(FReadRead);
    ReleaseSemaphore(FReaderSem, 1, nil);
  end;
  LeaveCriticalSection(FDataLock);
  WaitForSingleObject(FReaderSem, INFINITE);
end;

procedure TSimpleSynchronizer.StartWrite;
begin
  EnterCriticalSection(FDataLock);
  Inc(FActWrite);
  if FReadRead = 0 then begin
    Inc(FWriteWrite);
    ReleaseSemaphore(FWriterSem, 1, nil);
  end;
  LeaveCriticalSection(FDataLock);
  WaitForSingleObject(FWriterSem, INFINITE);
  EnterCriticalSection(FWriteLock);
end;

procedure TSimpleSynchronizer.EndRead;
begin
  EnterCriticalSection(FDataLock);
  Dec(FReadRead);
  Dec(FActRead);
  if FReadRead = 0 then begin
    while FWriteWrite < FActWrite do begin
      Inc(FWriteWrite);
      ReleaseSemaphore(FWriterSem, 1, nil);
    end;
  end;
  LeaveCriticalSection(FDataLock);
end;

procedure TSimpleSynchronizer.EndWrite;
begin
  LeaveCriticalSection(FWriteLock);
  EnterCriticalSection(FDataLock);
  Dec(FWriteWrite);
  Dec(FActWrite);
  if FActWrite = 0 then begin
    while FReadRead < FActRead do begin
      Inc(FReadRead);
      ReleaseSemaphore(FReaderSem, 1, nil);
    end;
  end;
  LeaveCriticalSection(FDataLock);
end;

{  TEventSynchronizer  }

constructor TEventSynchronizer.Create;
begin
  inherited Create;
  InitializeCriticalSection(FDataLock);
  InitializeCriticalSection(FWriteLock);
  FNoReaders := CreateEvent(nil, true, true, nil);
  FNoWriters := CreateEvent(nil, true, true, nil);
end;

destructor TEventSynchronizer.Destroy;
begin
  DeleteCriticalSection(FDataLock);
  DeleteCriticalSection(FWriteLock);
  CloseHandle(FNoReaders);
  CloseHandle(FNoWriters);
  inherited Destroy;
end;

procedure TEventSynchronizer.StartRead;
var
  Block: boolean;
begin
  EnterCriticalSection(FDatalock);
  if FReaders = 0 then ResetEvent(FNoReaders);
  Inc(FReaders);
  Block := FWriters > 0;
  LeaveCriticalSection(FDataLock);
  if Block then WaitForSingleObject(FNoWriters, INFINITE);
end;

procedure TEventSynchronizer.StartWrite;
var
  Block: boolean;
begin
  EnterCriticalSection(FDataLock);
  if FWriters = 0 then ResetEvent(FNoWriters);
  Inc(FWriters);
  Block := FReaders > 0;
  LeaveCriticalSection(FDataLock);
  if Block then WaitForSingleObject(FNoReaders, INFINITE);
  EnterCriticalSection(FWriteLock);
end;

procedure TEventSynchronizer.EndRead;
begin
  EnterCriticalSection(FDataLock);
  Dec(FReaders);
  if FReaders = 0 then SetEvent(FNoReaders);
  LeaveCriticalSection(FDataLock);
end;

procedure TEventSynchronizer.EndWrite;
begin
  LeaveCriticalSection(FWriteLock);
  EnterCriticalSection(FDataLock);
  Dec(FWriters);
  if FWriters = 0 then SetEvent(FNoWriters);
  LeaveCriticalSection(FDataLock);
end;

end.


// ищу примитив синхронизации, обеспечивающий доступ множества потоков на чтение, но только одного - на запись
// Multi Read Single Write

Обдумываю переделку своего TCP сервера. Буду делать асинхронную обработаку запросов (IOCP). 
Имеется несколько вспом. потоков (2..4), которые и обслуживают клиентов (пул потоков) . В каждом из них выделяется память под логи. 
В основном потоке (или ином потоке) планирую сделать переодическую (интервал 4 сек) выгрузку логов в файл. 
Как тут лучше синхронизировать? 
ЗЫ. Логи ведутся специально в каждом из потоков, что бы избавиться от "лишних" крит. секций.

// логирование http://www.viva64.com/ru/a/0018/

http://www.frolov-lib.ru/books/bsp/v26/ch5_4.htm

If your interested in setting the registry keys to enable output,
then check out the SetDbgPrintFiltering utility at http://www.osronline.com/downloads.

Потоки и их синхронизация http://forum.vingrad.ru/forum/topic-60076.html


