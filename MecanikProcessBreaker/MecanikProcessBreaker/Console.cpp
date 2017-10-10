//*******************************************************************************************************************//
//    __  __                      _ _      _____                               ____                 _             
//   |  \/  |                    (_) |    |  __ \                             |  _ \               | |            
//   | \  / | ___  ___ __ _ _ __  _| | __ | |__) | __ ___   ___ ___  ___ ___  | |_) |_ __ ___  __ _| | _____ _ __ 
//   | |\/| |/ _ \/ __/ _` | '_ \| | |/ / |  ___/ '__/ _ \ / __/ _ \/ __/ __| |  _ <| '__/ _ \/ _` | |/ / _ \ '__|
//   | |  | |  __/ (_| (_| | | | | |   <  | |   | | | (_) | (_|  __/\__ \__ \ | |_) | | |  __/ (_| |   <  __/ |   
//   |_|  |_|\___|\___\__,_|_| |_|_|_|\_\ |_|   |_|  \___/ \___\___||___/___/ |____/|_|  \___|\__,_|_|\_\___|_|   
//                                                                                                                
//	 This project was built as a "proof-of-concept" and nothing else. It is not ment for you to cause damage.
//   Not intended for malicious purposes, but to demonstrate how weak Windows is, and some "antihack" software.
//   NOT all the classes and code have been written by me, those files have no comments on top or the author's name.
//	 The original author of this project is me, Norbert Boros a.k.a Mecanik or Mr.Mecanik
// ------------------------------------------------------------------------------------------------------------------
// Looking for professional AntiHack ? Visit: http://liveguard-security.com/ | https://liveguardmu.com/
//*******************************************************************************************************************//

#include  "stdafx.h"
#include "Log.h"

// -----------------------------------------------------------------------
Console M_Console;
// -----------------------------------------------------------------------

Console::Console()
{
	// ----
}
// -----------------------------------------------------------------------

Console::~Console()
{
	// ----
}
// -----------------------------------------------------------------------

void __stdcall LoggerCore(PVOID pVoid)
{
	//	//
	char Temp[1024];
	// ----
	AllocConsole();
	SetConsoleTitleA(CONSOLETITLE);
	// ----
	while (true)
	{
		Sleep(100);
		M_Console.AddMessageToConsole(Temp);
		M_Console.LoadConsoleCommands(Temp);
	}
	//	//
}
// -----------------------------------------------------------------------

void Console::InitCore()
{
	AllocConsole();

	gLog.AddLog(1, "MECANIK_LOG");

	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);
	freopen("CONOUT$", "w", stderr);

	SetConsoleTitleA(CONSOLETITLE);

	this->ConsoleOutput(1, "#############################################################");
	this->ConsoleOutput(4, "[ Mecanik ] [ Process Breaker ] Hijack functions like a PRO");
	this->ConsoleOutput(1, "#############################################################");


}
// -----------------------------------------------------------------------

enum CNSL_E
{
	CONSOLE_RED = 1,
	CONSOLE_GREEN = 2,
	CONSOLE_BLUE = 3,
	CONSOLE_CYAN = 4,
	CONSOLE_YELLOW = 5,
	CONSOLE_WTF = 6,
};

void Console::ConsoleOutput(int Color, const char* Format, ...)
{
	SYSTEMTIME Time;
	GetLocalTime(&Time);
	// ----
	char Message[1024];
	char MessageOutPut[2048];
	DWORD dwBytes;
	// ----
	HANDLE Handle = GetStdHandle(STD_OUTPUT_HANDLE);
	char CorrectDate[MAX_PATH] = { 0 };
	// ----
	va_list pArguments;
	va_start(pArguments, Format);
	vsprintf_s(Message, Format, pArguments);
	va_end(pArguments);
	// ----
	sprintf_s(CorrectDate, "[%02d/%02d/%04d %02d:%02d:%02d:%04d]", Time.wDay, Time.wMonth, Time.wYear, Time.wHour, Time.wMinute, Time.wSecond, Time.wMilliseconds);
	//sprintf_s(CorrectDate, "[%02d:%02d:%02d]", Time.wHour, Time.wMinute, Time.wSecond);

	gLog.Output(LOG_DEBUG, Message);

	// ----
	sprintf_s(MessageOutPut, "%s %s\n", CorrectDate, Message);
	// ----
	switch (Color)
	{
		// Color Red Console.
		case CNSL_E::CONSOLE_RED: { SetConsoleTextAttribute(this->Handle(FALSE), FOREGROUND_RED | FOREGROUND_INTENSITY); } break;
		// Color Green Console.
		case CNSL_E::CONSOLE_GREEN: { SetConsoleTextAttribute(this->Handle(FALSE), FOREGROUND_GREEN | FOREGROUND_INTENSITY); } break;
		// Color Blue Console.
		case CNSL_E::CONSOLE_BLUE: { SetConsoleTextAttribute(this->Handle(FALSE), FOREGROUND_BLUE | FOREGROUND_INTENSITY); } break;
		// Color Cyan Console.
		case CNSL_E::CONSOLE_CYAN: { SetConsoleTextAttribute(this->Handle(FALSE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); } break;
		// Color Yellow Console.
		case CNSL_E::CONSOLE_YELLOW: { SetConsoleTextAttribute(this->Handle(FALSE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); } break;
		// new color Console.
		case CNSL_E::CONSOLE_WTF: { SetConsoleTextAttribute(this->Handle(FALSE), FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); } break;
	}
	// ----
	WriteFile(Handle, MessageOutPut, strlen(MessageOutPut), &dwBytes, NULL);
}
// -----------------------------------------------------------------------

int Console::AddMessageToConsole(char* Buffer)
{
	//	//
	char Text[1024];
	DWORD dwBytes;
	// ----
	memset(Text, 0x00, 1024);
	memset(Buffer, 0x00, 1024);
	// ----
	ReadFile(Handle(TRUE), Text, 1024, &dwBytes, NULL);
	// ----
	strncpy(Buffer, Text, strlen(Text) - 2);
	// ----
	////
	return dwBytes;
}
// -----------------------------------------------------------------------

HANDLE Console::Handle(BOOL gImput)
{
	if (gImput == TRUE) {
		return GetStdHandle(STD_INPUT_HANDLE);
	} else {
		return GetStdHandle(STD_OUTPUT_HANDLE);
	}
}
// -----------------------------------------------------------------------

void Console::LoadConsoleCommands(char* gImput)
{
	char Temp[1024] = { 0 };
	// ----
	if (!strncmp(gImput, "/clear", 7))
	{
		system("cls");
		return;
	}
	// ----
	else if ((!strncmp(gImput, "/exit", 5)) ||
		(!strncmp(gImput, "/quit", 5)) ||
		(!strncmp(gImput, "/close", 5)))
	{
		exit(1);
		return;
	}
	//	//
}

void Console::Terminate()
{
	exit(1);
	return;
}
// -----------------------------------------------------------------------
extern Console M_Console;
// -----------------------------------------------------------------------