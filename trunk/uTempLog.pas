unit uTempLog;

// Author: acDev
// Годится для глобального логирования в процессе, в котором не более 60 потоков логируют в файлы и консоль.

interface

uses Windows, Classes, SyncObjs;

const
  TempLogMaxLineLen = 512 - 32;
  TempLogDefaultLineCount = 8192;

type
  PTempLogLineRec = ^TTempLogLineRec;
  TTempLogLineRec = packed record
    LineNum: Cardinal;
    ThreadID: Cardinal;     // 04  // источник лога (ID потока)
    ClientID: Cardinal;     // 08  // идентификатор удалённого клиента (или его IP адресс)
    Time: TSystemTime;      // 12
    ModuleID: Byte;         // 28  // источник лога  // 1 - удалённые клиенты и прочее  // 2 - удалённые игровые сервера (RCON)
    LogLevel: Byte;         // 29  // 0 - Error   1 - Log   3 - Debug   5 - DevelLog
    LineLen: Word;          // 30
    LineData: array [0..TempLogMaxLineLen-1] of Char;  // 32   
  end;

  PTempLogBuf = ^TTempLogBuf;
  TTempLogBuf = array [0..1] of TTempLogLineRec;

  TLogModuleParam = packed record
    LogToFile: Boolean;
    LogToConsole: Boolean;
    Dir: String;
    FilePrefix: String;
    LineBuf: String;     // буфер строк, готовый для добавления в конец файла
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
    FLogParam: array [0..2] of TLogModuleParam;

    constructor Create(LineCount: Cardinal = TempLogDefaultLineCount);
    destructor Destroy; override;
    function AddLine(ModuleID: Byte; LogLevel: Byte; ThreadID: Cardinal; ClientID: Cardinal; const Line: String): Boolean;
    function GenerateTxtLine(DebugLog: Boolean; ModuleID: Byte; ThreadID: Cardinal; ClientID: Cardinal; Time: PSystemTime; Line: PChar; LineLen: Cardinal): String;
    function SetLogParams(ModuleID: Byte; LogToFile, LogToConsole: Boolean; const Dir: String; const FilePrefix: String): Boolean;

    function CreateThreadWriteLog(Priority: TThreadPriority = tpHigher): Boolean;
    function DestroyThreadWriteLog(TimeOut: Integer = 300): Boolean;
    function StartThreadWriteLog: Boolean;

    property LogBuf: PTempLogBuf read FLogBuf;
  end;

  TWriteLogThread = class(TThread)
  private
    FTempBuf: TTempLogBuffer;
  protected
    function WriteLog: Integer;
    procedure Execute; override;
  end;

implementation

uses SysUtils;

var
  TempLogGlobLineCounter: Cardinal = 0;   // счётчик ID строк

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
end;

destructor TTempLogBuffer.Destroy;
begin
  FMemStream.Free;
end;

function TTempLogBuffer.SetLogParams(ModuleID: Byte; LogToFile, LogToConsole: Boolean; const Dir: String; const FilePrefix: String): Boolean;
begin
  Result := False;
  if ModuleID > 2 then Exit;
  if (Dir = '') or (FilePrefix = '') then Exit;
  if not ForceDirectories(Dir) then Exit;
  FLogParam[ModuleID].LogToFile := LogToFile;
  FLogParam[ModuleID].LogToConsole := LogToConsole;
  FLogParam[ModuleID].Dir := Dir;
  FLogParam[ModuleID].FilePrefix := Dir+'\'+FilePrefix;
  FLogParam[ModuleID].LineBuf := '';
  Result := True;
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
  if FDebugLog then begin
    s := GenerateTxtLine(True, ModuleID, ThreadID, ClientID, nil, @Line[1], Length(Line));
    if s <> '' then OutputDebugString(PChar(s));
  end;

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
  if d > (FLineCount - 66) then Exit;  // строка, которая описана чуть выше

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

function DateTimeToStrAdv(t: PSystemTime; AFmt: Integer): String;
begin
  Result := IntToStr(t^.wYear);
  if t^.wMonth  < 10 then Result := Result+'-0'+IntToStr(t^.wMonth)  else Result := Result+'-'+IntToStr(t^.wMonth);
  if t^.wDay    < 10 then Result := Result+'-0'+IntToStr(t^.wDay)    else Result := Result+'-'+IntToStr(t^.wDay);
  if t^.wHour   < 10 then Result := Result+' 0'+IntToStr(t^.wHour)   else Result := Result+' '+IntToStr(t^.wHour);
  if t^.wMinute < 10 then Result := Result+':0'+IntToStr(t^.wMinute) else Result := Result+':'+IntToStr(t^.wMinute);
  if t^.wSecond < 10 then Result := Result+':0'+IntToStr(t^.wSecond) else Result := Result+':'+IntToStr(t^.wSecond);
end;

function TTempLogBuffer.GenerateTxtLine(DebugLog: Boolean; ModuleID: Byte; ThreadID: Cardinal; ClientID: Cardinal;
                                        Time: PSystemTime; Line: PChar; LineLen: Cardinal): String;
var
  st: TSystemTime;
  n: Integer;
begin
  Result := '';
  if (ModuleID <> 1)and(ModuleID <> 2) then Exit;
  if DebugLog then begin
    if ModuleID = 1 then Result := '[HPserv] ';
    if ModuleID = 2 then Result := '[HPsysd] ';
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
  FThread := TWriteLogThread.Create(True);   // поток создаться, но не запустится
  FThread.FTempBuf := Self;
  FThread.Priority := Priority;
end;

function TTempLogBuffer.DestroyThreadWriteLog(TimeOut: Integer = 300): Boolean;
var
  i, k: Integer;
begin
  if FThread.Terminated then begin Result := True; Exit; end;
  Result := False;
  FThread.Terminate;
  if TimeOut > 300 then begin
    k := TimeOut div 100;
    for i:=0 to k do begin
      Sleep(100);
      if FThread.Terminated then begin Result := True; Exit; end;
    end;
  end else begin
    Sleep(Cardinal(TimeOut));
    if FThread.Terminated then begin Result := True; Exit; end;
  end;
end;

function TTempLogBuffer.StartThreadWriteLog: Boolean;
begin
  FThread.Resume;
end;

{ TWriteLogThread }

function TWriteLogThread.WriteLog: Integer;
var
  FileLog: TStringList;
  buf: PTempLogBuf;
  r: PTempLogLineRec;
  w, i, n, v, p: Cardinal;
  s, Filename: String;
  m: Byte;
  lf: Boolean;
  fs: TFileStream;
begin
  Result := 0;
  buf := FTempBuf.FLogBuf;
  v := FTempBuf.FLastReadLineNum;
  if (v = 0) and (buf^[0].ModuleID = $FE) then begin
    //if (buf^[1].ModuleID > 100) or (buf^[1].LineNum = 0) then Exit;   // логировать ещё нечего
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
      s := IntToHex(n, 8) + ' ' + s;
      // логируем s 
      if (m <= 2) then begin
        if FTempBuf.FLogParam[m].LogToFile then begin
          FTempBuf.FLogParam[m].LineBuf := FTempBuf.FLogParam[m].LineBuf + s + #13#10;
          lf := True;
        end;
        if FTempBuf.FLogParam[m].LogToConsole then begin
          System.Writeln(s);
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
    end;  
  until Terminated;
end;


end.
