{$IOCHECKS OFF}
{$APPTYPE CONSOLE}

program HPServCon;

uses
  Windows, SysUtils,
  HPScktSrvr, uHPServCon, uHPServClient;

const
  AppName: array [0..9] of Char = 'HPServCon'#0;

var
  ParStr: String;
  Int32: Integer;
  hMutex : THandle;
  FSecAttr: TSecurityAttributes;
  FSecDesc: TSecurityDescriptor;
  iExitCode: Cardinal;
  bProcessTerminate: Boolean;

function ConsoleProc(CtrlType: DWORD): Bool; stdcall; far;
begin
  case CtrlType of
    CTRL_C_EVENT,
    CTRL_BREAK_EVENT,
    CTRL_CLOSE_EVENT,
    CTRL_LOGOFF_EVENT,
    CTRL_SHUTDOWN_EVENT: begin
      bProcessTerminate := True;
    end;
  end;
  Result := True;
end;

begin
  HPServerPort := 5000;
  if (ParamCount > 0) then begin
    for Int32:=1 to ParamCount do begin
      ParStr := ParamStr(Int32);
      if Pos('/port=', ParStr) = 1 then HPServerPort := StrToIntDef(Copy(ParStr, 7, Length(ParStr)-7+1), 5000);
    end;
  end;
  ParStr := AppName+'_'+IntToStr(HPServerPort);
  hMutex := CreateMutex(nil, True , PAnsiChar(ParStr));
  if GetLastError = ERROR_ALREADY_EXISTS then begin
    CloseHandle(hMutex);
    Halt(1);
  end;

  bProcessTerminate := False;
  iExitCode := 0;

  HPSrv := THPServerCon.Create(ExtractFileDir(ParamStr(0)));
  try
    with HPSrv.HPServerSocket do begin
      MinimumWorkThreads := 0;
      Port := IntToStr(HPServerPort);
      AcceptorsCount := 30;
      MinimumAcceptors := 15;
      AcceptorPriority := apLow;
      OnClientBeforeAccept := HPSrv.HPSrvClientBeforeAccept;
      OnClientConnect := HPSrv.HPSrvClientConnect;
      OnClientDisconnect := HPSrv.HPSrvClientDisconnect;
      OnReadComplete := HPSrv.HPSrvReadComplete;
      OnWriteComplete := HPSrv.HPSrvWriteComplete;
    end;
    if not HPSrv.ServerOpen(IntToStr(HPServerPort)) then begin iExitCode := 10; Exit; end;
    Windows.SetConsoleCtrlHandler(@ConsoleProc, True);
    repeat
      Sleep(250);
      // ожидание команды завершения
      if bProcessTerminate then begin iExitCode := 0; HPSrv.ServerClose; Exit; end;
    until False;
  finally
    HPSrv.Free;
    //CloseHandle(FChildStdinWr);
  end;
  Writeln('--- CLOSE ---');
  Halt(iExitCode);
end.



