// Date:   2011-02-22
// Author: acDev

// Годится для глобального логирования в процессе, в котором не более 60 потоков логируют в файлы и консоль.

unit uTempLog;

interface

uses Windows, Classes, SyncObjs;

const
  TempLogMaxLineLen = 512 - 32;
  TempLogDefaultLineCount = 8192;

threadvar
  iCurrentThreadID: Cardinal;

var
  ThreadClientList: TList = nil;    // используется при логировании (что бы логировать номер потока, а не его ID)

const
  MaxIndexOfLogParam = 2;
  ODSPrefix1 = '[HPserv] ';    // префикс строк, логируемых сразу через OutputDebugString
  ODSPrefix2 = '[HPsysd] ';    // префикс строк, логируемых сразу через OutputDebugString

type
  PTempLogLineRec = ^TTempLogLineRec;
  TTempLogLineRec = packed record
    LineNum: Cardinal;
    ThreadID: Cardinal;     // 04  // источник лога (ID потока)
    ClientID: Cardinal;     // 08  // идентификатор удалённого клиента (или его IP адресс)
    Time: TSystemTime;      // 12
    ModuleID: Byte;         // 28  // источник лога  // 1 - удалённые клиенты и прочее  // 2 - other    // должна быть выровнена на 4 байта
    LogLevel: Byte;         // 29  // 0 - Error   1 - Log   2 - Debug   5 - DevelLog
    LineLen: Word;          // 30
    LineData: array [0..TempLogMaxLineLen-1] of Char;  // 32
  end;

  PTempLogBuf = ^TTempLogBuf;
  TTempLogBuf = array [0..1] of TTempLogLineRec;

  TLogModuleParam = packed record
    LogToFile: Boolean;
    LogToConsole: Boolean;
    DublicateTo: Byte;      // номер лога, в лог-файл которого нужно продублировать строку
    Dummy: Byte;
    Dir: String;
    FilePrefix: String;
    ODSPrefix: String;
    LineBuf: String;        // буфер строк, готовый для добавления в конец файла
  end;

type
  TWriteLogThread = class;

  TTempLogBuffer = class
  private
    FMemStream: TMemoryStream;
    FLogBuf: PTempLogBuf;
    FLineCount: Cardinal;        // количество строк в буфере
    FLineNumMask: Cardinal;
    FLastReadLineNum: Cardinal;  // глоб. номер последнй прочитанной из буфера строки
  public
    FThread: TWriteLogThread;
    FDebugLog: Boolean;          // использовать отладочные сообщения Win32
    FWritePeriod: Integer;       // переодичность скидывания лога в файл и в консоль (милисекунды)
    FLogParam: array [0..MaxIndexOfLogParam] of TLogModuleParam;

    constructor Create(LineCount: Cardinal = TempLogDefaultLineCount);
    destructor Destroy; override;
    function AddLine(ModuleID: Byte; LogLevel: Byte; ThreadID: Cardinal; ClientID: Cardinal; const Line: String): Boolean;
    function AddLineTC(ModuleID: Byte; LogLevel: Byte; ClientID: Cardinal; const Line: String): Boolean;
    function AddLineT(ModuleID: Byte; LogLevel: Byte; const Line: String): Boolean;
    function AddLineS(ModuleID: Byte; LogLevel: Byte; const Line: String): Boolean;
    function AddLine1S(LogLevel: Byte; const Line: String): Boolean;
    function GenerateTxtLine(DebugLog: Boolean; ModuleID: Byte; ThreadID: Cardinal; ClientID: Cardinal; Time: PSystemTime; Line: PChar; LineLen: Cardinal): String;
    function SetLogParams(ModuleID: Byte; LogToFile, LogToConsole: Boolean; const Dir: String; const FilePrefix: String): Boolean;
    function SetLogDuplicate(SourceModuleID: Byte; DestinationModuleID: Byte): Boolean;
    function SetLogParamsODS(ModuleID: Byte; const OutputDebugStringPrefix: String): Boolean;
    procedure SetWritePeriod(Period: Integer);

    function CreateThreadWriteLog(Priority: TThreadPriority = tpHigher): Boolean;
    function DestroyThreadWriteLog(TimeOut: Integer = 300): Boolean;
    function StartThreadWriteLog: Boolean;
    procedure SetThreadPriority(Priority: TThreadPriority);
    function GetThreadCurrentPriority: TThreadPriority;

    property LogBuf: PTempLogBuf read FLogBuf;
  end;

  TWriteLogThread = class(TThread)
  private
    FStatus: Integer;
    FTempBuf: TTempLogBuffer;
  protected
    function WriteLog: Integer;
    procedure Execute; override;
  end;

function GetCurrentThreadNumber(ThreadID: Cardinal): Cardinal;   // пригодится везде

implementation

uses SysUtils;

var
  TempLogGlobLineCounter: Cardinal = 0;   // счётчик ID строк

// -------------------------------------------------------------------------------------------------------
function GetCurrentThreadNumber(ThreadID: Cardinal): Cardinal;
begin
  if ThreadID = $FFFFFFFF then begin Result := $FFFFFFFF; Exit; end;
  if ThreadID = $FFFFFFFE then begin
    if iCurrentThreadId = 0 then begin
      ThreadID := Windows.GetCurrentThreadId;
      iCurrentThreadId := ThreadID;
    end else begin
      ThreadID := iCurrentThreadId;
    end;
  end else
  if ThreadID = $FFFFFFFD then begin
    ThreadID := Windows.GetCurrentThreadId;
  end;
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

// --------------------------------------------------------------------------------------------------------
constructor TTempLogBuffer.Create(LineCount: Cardinal = TempLogDefaultLineCount);
var
  i: Integer;
  d: Cardinal;
begin
  FThread := nil;
  if LineCount <= 1024 then LineCount := 1024 else
  if LineCount <= 2*1024 then LineCount := 2*1024 else
  if LineCount <= 4*1024 then LineCount := 4*1024 else
  if LineCount <= 8*1024 then LineCount := 8*1024 else
  if LineCount <= 16*1024 then LineCount := 16*1024 else LineCount := 32*1024;
  FLineCount := LineCount;
  FLineNumMask := FLineCount - 1;
  FMemStream := TMemoryStream.Create;
  FMemStream.SetSize(SizeOf(TTempLogLineRec)*FLineCount);
  FLogBuf := PTempLogBuf(FMemStream.Memory);
  FillChar(FMemStream.Memory^, FMemStream.Size, 0);
  for i:=0 to FLineNumMask do begin
    FLogBuf^[i].ModuleID := $FE;  // означает что строка эта в счёт не принимается
  end;
  FLastReadLineNum := 0;
  FDebugLog := True;
  FWritePeriod := 1000;    // по умолчанию скидываем лог в файл каждую секунду
  FillChar(FLogParam, SizeOf(FLogParam), 0);
  for i:=0 to High(FLogParam) do begin
    FLogParam[i].LineBuf := '';
  end;  
end;

destructor TTempLogBuffer.Destroy;
begin
  FMemStream.Free;
end;

function TTempLogBuffer.SetLogParams(ModuleID: Byte; LogToFile, LogToConsole: Boolean; const Dir: String; const FilePrefix: String): Boolean;
begin
  Result := False;
  if ModuleID > MaxIndexOfLogParam then Exit;
  if (Dir = '') or (FilePrefix = '') then Exit;
  if not ForceDirectories(Dir) then Exit;
  FLogParam[ModuleID].LogToFile := LogToFile;
  FLogParam[ModuleID].LogToConsole := LogToConsole;
  FLogParam[ModuleID].Dir := Dir;
  FLogParam[ModuleID].FilePrefix := Dir+'\'+FilePrefix;
  FLogParam[ModuleID].ODSPrefix := '';
  FLogParam[ModuleID].LineBuf := '';
  FLogParam[ModuleID].DublicateTo := 0;  // значит никуда не нужно дублировать лог-файл
  Result := True;
end;

function TTempLogBuffer.SetLogDuplicate(SourceModuleID: Byte; DestinationModuleID: Byte): Boolean;
begin
  Result := False;
  if (SourceModuleID > MaxIndexOfLogParam) or (DestinationModuleID > MaxIndexOfLogParam) then Exit;
  FLogParam[SourceModuleID].DublicateTo := DestinationModuleID;
  Result := True;
end;

function TTempLogBuffer.SetLogParamsODS(ModuleID: Byte; const OutputDebugStringPrefix: String): Boolean;
begin
  Result := False;
  if ModuleID > MaxIndexOfLogParam then Exit;
  FLogParam[ModuleID].ODSPrefix := OutputDebugStringPrefix;
  Result := True;
end;

procedure TTempLogBuffer.SetWritePeriod(Period: Integer);
begin
  if Period < 1000 then Period := 1000;
  FWritePeriod := Period;
end;

function TTempLogBuffer.AddLine(ModuleID: Byte; LogLevel: Byte; ThreadID: Cardinal; ClientID: Cardinal; const Line: String): Boolean;
var
  g, n: Cardinal;
  NextLinePos: Cardinal;
  d: Cardinal;
  LineNum: Cardinal;
  LineLen: Cardinal;
  p: PTempLogLineRec;
  s: String;
begin
  Result := False;
  // тут мы проверяем на скорость "опустошения буфера"  // если не успеваем "опустошать", то и не логируем более
  // 66 нужно, т.к. данный код исполняется в нескольких потоках, количество которых явно меньше 66 !!!
  // if TempLogGlobLineCounter - FLastReadLineNum > (FLineCount - 66) then Exit;

  // Примечание: данный механизм работает корректно только в том случае, когда FLastReadLineNum <= TempLogGlobLineCounter
  // за этим надо внимательно следить !!!

  n := FLastReadLineNum;
  g := TempLogGlobLineCounter;
  // чуть выше не было учтено переполнение счётчика TempLogGlobLineCounter
  if ((n shr 31) <> 0) and (g < n) then begin
    // это означает что счётчик TempLogGlobLineCounter убежал на круг дальше, чем FLastReadLineNum
    d := $FFFFFFFF - n;
    d := g + 1 + d;
  end else begin
    d := g - n;
  end;
  if not(d > (FLineCount - 66)) then begin    // условие описано чуть выше
    Integer(LineNum) := Windows.InterlockedIncrement(Integer(TempLogGlobLineCounter));
    NextLinePos := LineNum and FLineNumMask;
    p := @FLogBuf^[NextLinePos];
    p^.ModuleID := $FF;       // даём признак того, что мы только начали заполнять эту строку
    p^.ThreadID := ThreadID;
    p^.ClientID := ClientID;
    Windows.GetLocalTime(p^.Time);
    p^.LogLevel := LogLevel;
    LineLen := Length(Line);
    if LineLen > TempLogMaxLineLen then LineLen := TempLogMaxLineLen;
    p^.LineLen := LineLen;
    if LineLen > 0 then System.Move(Line[1], p^.LineData[0], LineLen);
    Windows.InterlockedExchange(Integer(p^.LineNum), Integer(LineNum));    //  p^.LineNum := LineNum;
    p^.ModuleID := ModuleID;  // даём признак того, что мы закончили вставку новой строки в буфер
    Result := True;
  end;
  if FDebugLog then begin
    s := GenerateTxtLine(True, ModuleID, ThreadID, ClientID, nil, @Line[1], Length(Line));
    if s <> '' then OutputDebugString(PChar(s));
  end;
end;

// параметр ThreadID вычисляется автоматически
function TTempLogBuffer.AddLineTC(ModuleID: Byte; LogLevel: Byte; ClientID: Cardinal; const Line: String): Boolean;
var
  aThreadID: Cardinal;
begin
  aThreadID := GetCurrentThreadNumber($FFFFFFFE);
  Result := AddLine(ModuleID, LogLevel, aThreadID, ClientID, Line);
end;

// параметр ThreadID вычисляется автоматически  // параметр ClientID пустой
function TTempLogBuffer.AddLineT(ModuleID: Byte; LogLevel: Byte; const Line: String): Boolean;
begin
  Result := AddLineTC(ModuleID, LogLevel, $FFFFFFFF, Line);
end;

// S = Simple
function TTempLogBuffer.AddLineS(ModuleID: Byte; LogLevel: Byte; const Line: String): Boolean;
begin
  Result := AddLine(ModuleID, LogLevel, $FFFFFFFF, $FFFFFFFF, Line);
end;

function TTempLogBuffer.AddLine1S(LogLevel: Byte; const Line: String): Boolean;
begin
  Result := AddLine(1, LogLevel, $FFFFFFFF, $FFFFFFFF, Line);
end;

function DigitToChar(b: Byte): Char;
begin
  if b >= 10 then b := b mod 10;
  Result := Char(b + Ord('0'));
end;

function DateTimeToStrAdv(t: PSystemTime; AFmt: Integer): String;
begin
  Result := IntToStr(t^.wYear);
  if t^.wYear < 10 then Result := '000'+Result else
  if t^.wYear < 100 then Result := '00'+Result else
  if t^.wYear < 1000 then Result := '0'+Result;
  Result := Result+'-'+DigitToChar(t^.wMonth  div 10)+DigitToChar(t^.wMonth  mod 10);
  Result := Result+'-'+DigitToChar(t^.wDay    div 10)+DigitToChar(t^.wDay    mod 10);
  Result := Result+' '+DigitToChar(t^.wHour   div 10)+DigitToChar(t^.wHour   mod 10);
  Result := Result+':'+DigitToChar(t^.wMinute div 10)+DigitToChar(t^.wMinute mod 10);
  Result := Result+':'+DigitToChar(t^.wSecond div 10)+DigitToChar(t^.wSecond mod 10);
end;

function TTempLogBuffer.GenerateTxtLine(DebugLog: Boolean; ModuleID: Byte; ThreadID: Cardinal; ClientID: Cardinal;
                                        Time: PSystemTime; Line: PChar; LineLen: Cardinal): String;
var
  st: TSystemTime;
  n: Integer;
begin
  Result := '';
  if (ModuleID = 0) or (ModuleID > 7) then Exit;
  if DebugLog then begin
    Result := FLogParam[ModuleID].ODSPrefix;
  end;
  if Time = nil then begin
    Windows.GetLocalTime(st);
    Time := @st;
  end;
  Result := Result + '<' + DateTimeToStrAdv(Time, 0) + '>  ';
  if ThreadID < 100 then begin
    if ThreadID < 10 then Result := Result + '0' + IntToStr(ThreadID) else Result := Result + IntToStr(ThreadID);
    Result := Result + ' ';
  end else begin
    //if ClientID <> $FFFFFFFF then
      Result := Result + '   ';
  end;

  if ClientID <> $FFFFFFFF then begin
    Result := Result + '[' + IntToHex(ClientID, 8) + '] ';
  end;

  if LineLen > 0 then begin
    n := Length(Result);
    SetLength(Result, n + LineLen);
    System.Move(Line[0], Result[n+1], LineLen);
  end;
end;

function TTempLogBuffer.CreateThreadWriteLog(Priority: TThreadPriority = tpHigher): Boolean;
begin
  FThread := TWriteLogThread.Create(True);   // поток создастся, но не запустится
  FThread.FreeOnTerminate := False;
  FThread.FTempBuf := Self;
  FThread.Priority := Priority;
  FThread.FStatus := 0;
end;

function TTempLogBuffer.DestroyThreadWriteLog(TimeOut: Integer = 300): Boolean;
var
  i, k: Integer;
begin
  Result := False;
  if (FThread.FStatus = 0) then begin FThread.Resume; FThread.Terminate; Sleep(18); end;
  if (FThread.FStatus = 2) then begin FThread.Free; Result := True; Exit; end;
  FThread.Terminate;
  if TimeOut >= 200 then begin
    k := (TimeOut-1) div 100;
    for i:=0 to k do begin
      Sleep(100);
      if FThread.FStatus = 2 then begin FThread.Free; Result := True; Exit; end;
    end;
  end else begin
    Sleep(Cardinal(TimeOut));
    if FThread.FStatus = 2 then begin FThread.Free; Result := True; Exit; end;
  end;
end;

function TTempLogBuffer.StartThreadWriteLog: Boolean;
begin
  FThread.Resume;
end;

procedure TTempLogBuffer.SetThreadPriority(Priority: TThreadPriority);
begin
  if not Assigned(FThread) then Exit;
  FThread.Priority := Priority;
end;

function TTempLogBuffer.GetThreadCurrentPriority: TThreadPriority;
begin
  if not Assigned(FThread) then begin Result := TThreadPriority(-1); Exit; end;
  Result := FThread.Priority;
end;

{ TWriteLogThread }

function TWriteLogThread.WriteLog: Integer;
var
  FileLog: TStringList;
  buf: PTempLogBuf;
  r: PTempLogLineRec;
  w, i, n, v, p: Cardinal;
  s, Filename: String;
  m, m2: Byte;
  lf: Boolean;
  fs: TFileStream;
begin
  Result := 0;
  buf := FTempBuf.FLogBuf;
  v := FTempBuf.FLastReadLineNum;
  if (v = 0) and (buf^[0].ModuleID = $FE) then begin
    if (buf^[1].ModuleID > 100) or (buf^[1].LineNum <> 1) then Exit;  // логировать ещё нечего
    buf^[0].ModuleID := 0;   // даём отмашку полноценному логированию
  end;
  w := 0;
  n := v + 1;  // строка, с которой будем работать
  p := n and FTempBuf.FLineNumMask;
  r := @buf^[p];
  m := r^.ModuleID;
  if (m > 100) or (r^.LineNum <> n) then Exit;   // в буфер ещё не добавлялись новые данные
  for i:=0 to High(FTempBuf.FLogParam) do begin
    FTempBuf.FLogParam[i].LineBuf := '';
  end;
  lf := False;
  repeat
    s := FTempBuf.GenerateTxtLine(False, r^.ModuleID, r^.ThreadID, r^.ClientID, @r^.Time, @r^.LineData[0], r^.LineLen);
    if s <> '' then begin
      //s := IntToHex(n, 8) + ' ' + s;
      // логируем s 
      if (m <= MaxIndexOfLogParam) then begin
        if FTempBuf.FLogParam[m].LogToFile then begin
          FTempBuf.FLogParam[m].LineBuf := FTempBuf.FLogParam[m].LineBuf + s + #13#10;
          lf := True;
        end;
        m2 := FTempBuf.FLogParam[m].DublicateTo;
        if m2 > 0 then begin
          if FTempBuf.FLogParam[m2].LogToFile then begin
            FTempBuf.FLogParam[m2].LineBuf := FTempBuf.FLogParam[m2].LineBuf + s + #13#10;
            lf := True;
          end;
        end;
        if FTempBuf.FLogParam[m].LogToConsole then begin
          System.Writeln(s);
        end else
        if m2 > 0 then begin
          if FTempBuf.FLogParam[m2].LogToConsole then begin
            System.Writeln(s);
          end;  
        end;
      end;
      Inc(w);
    end;
    v := n;
    Inc(n);
    p := n and FTempBuf.FLineNumMask;
    r := @buf^[p];
    m := r^.ModuleID;
    if (m > 100) or (r^.LineNum <> n) then begin   // добрались до конца логов
      FTempBuf.FLastReadLineNum := v;   // запоминаем на чём мы остановились , что бы после попробовать начать с этой позиции
      if lf then begin
        for i:=0 to High(FTempBuf.FLogParam) do begin
          if FTempBuf.FLogParam[i].LineBuf = '' then Continue;
          DateTimeToString(s, 'yyyymmdd', SysUtils.Date);
          Filename := FTempBuf.FLogParam[i].FilePrefix + s + '.log';
          if not FileExists(Filename) then begin
            fs := TFileStream.Create(Filename, fmCreate);
          end else begin
            fs := TFileStream.Create(Filename, fmOpenReadWrite or fmShareDenyWrite);
            fs.Position := fs.Size;
          end;
          try
            fs.WriteBuffer(FTempBuf.FLogParam[i].LineBuf[1], Length(FTempBuf.FLogParam[i].LineBuf));
          finally
            fs.Free;
          end;
        end;
      end;
      Break;   // выходим из функции сброса лога в файл и на консоль
    end;
  until False;
  Result := w;
end;

procedure TWriteLogThread.Execute;
var
  d, n, k: Cardinal;
begin
  FStatus := 1;
  if Terminated then begin FStatus := 2; Exit; end;
  n := 0;   // счётчик работы потока
  k := 0;   // значение счётчика n , при котором велась работа с логами
  repeat
    Sleep(100);
    Inc(n);
    if ((k shr 31) <> 0) and (n < k) then begin // это означает что счётчик n убежал на круг дальше, чем k
      d := $FFFFFFFF - k;
      d := n + d;
    end else begin
      d := n - k;
    end;
    if not Terminated then begin
      if d*100 >= FTempBuf.FWritePeriod then begin
        Self.WriteLog;
        k := n;
      end;
    end else begin
      Self.WriteLog;
    end;
  until Terminated;
  FStatus := 2;
end;


end.



