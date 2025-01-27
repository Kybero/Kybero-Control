rule Adware_InstallCore_A_con
{
	meta:
		author = "FileScan.IO Engine v1.1.0-d133568"
		date = "2024-05-14"
		sample = "93bc218fa7956dc4eb8d19f7fe8c8ebb2e0b60f06ff221bbab6e62b56fc94f6a"
		score = 75
		tags = "fingerprint,installer,lolbin,overlay,packed,setupapi,shell32"
		isWeakRule = false

	strings:

		//IOC patterns
		$req0 = "* flD.ch^}{1?"
		$req1 = "005/WindowsSettings\">true</dpiAware>\r\n    </windowsSettings>\r\n</application>\r\n<compatibility xmlns=\"urn:schemas-microsoft-com:co"
		$req2 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\r\n<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0"
		$req3 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline"
		$req4 = "Software\\Borland\\Delphi\\Locales"
		$req5 = "Software\\Borland\\Locales"
		$req6 = "Software\\CodeGear\\Locales"
		$req7 = "Software\\Embarcadero\\Locales"

		//optional strings
		$opt0 = "Access violation"
		$opt1 = "AdjustTokenPrivileges"
		$opt2 = "BeginInvoke"
		$opt3 = "CallWindowProcW"
		$opt4 = "CreateDirectoryW"
		$opt5 = "CreateEventW"
		$opt6 = "CreateFileW"
		$opt7 = "CreateProcessW"
		$opt8 = "CreateThread"
		$opt9 = "CreateWindowExW"
		$opt10 = "DeleteCriticalSection"
		$opt11 = "DeleteFileW"
		$opt12 = "DestroyWindow"
		$opt13 = "DispatchMessageW"
		$opt14 = "DisplayName"
		$opt15 = "EndInvoke"
		$opt16 = "EnterCriticalSection"
		$opt17 = "EnumCalendarInfoW"
		$opt18 = "ExitProcess"
		$opt19 = "ExitThread"
		$opt20 = "ExitWindowsEx"
		$opt21 = "FindFirstFileW"
		$opt22 = "FindResourceW"
		$opt23 = "FormatMessageW"
		$opt24 = "FreeLibrary"
		$opt25 = "GetCommandLineW"
		$opt26 = "GetCurrentProcess"
		$opt27 = "GetCurrentThread"
		$opt28 = "GetCurrentThreadId"
		$opt29 = "GetDateFormatW"
		$opt30 = "GetDiskFreeSpaceExW"
		$opt31 = "GetDiskFreeSpaceW"
		$opt32 = "GetEnvironmentVariableW"
		$opt33 = "GetExitCodeProcess"
		$opt34 = "GetExitCodeThread"
		$opt35 = "GetFileAttributesW"
		$opt36 = "GetFileSize"
		$opt37 = "GetFileVersionInfoSizeW"
		$opt38 = "GetFileVersionInfoW"
		$opt39 = "GetFullPathNameW"
		$opt40 = "GetLastError"
		$opt41 = "GetLocalTime"
		$opt42 = "GetLocaleInfoW"
		$opt43 = "GetLogicalProcessorInformation"
		$opt44 = "GetModuleFileNameW"
		$opt45 = "GetModuleHandleW"
		$opt46 = "GetNativeSystemInfo"
		$opt47 = "GetProcAddress"
		$opt48 = "GetStartupInfoW"
		$opt49 = "GetStdHandle"
		$opt50 = "GetSystemDirectoryW"
		$opt51 = "GetSystemInfo"
		$opt52 = "GetSystemMetrics"
		$opt53 = "GetThreadLocale"
		$opt54 = "GetThreadPriority"
		$opt55 = "GetTickCount"
		$opt56 = "GetVersion"
		$opt57 = "GetVersionExW"
		$opt58 = "GetWindowsDirectoryW"
		$opt59 = "HeapCreate"
		$opt60 = "HeapDestroy"
		$opt61 = "InitializeCriticalSection"
		$opt62 = "Invalid NULL variant operation%Invalid variant operation (%s%.8x)\n%s5Could not convert variant of type (%s) into type (%s)=Overf"
		$opt63 = "LeaveCriticalSection"
		$opt64 = "LoadLibraryA"
		$opt65 = "LoadLibraryExW"
		$opt66 = "LoadLibraryW"
		$opt67 = "LoadResource"
		$opt68 = "LoadStringW"
		$opt69 = "LocalAlloc"
		$opt70 = "LockResource"
		$opt71 = "LookupPrivilegeValueW"
		$opt72 = "MsgWaitForMultipleObjects"
		$opt73 = "NetApiBufferFree"
		$opt74 = "NetWkstaGetInfo"
		$opt75 = "OpenProcessToken"
		$opt76 = "PeekMessageW"
		$opt77 = "QueryPerformanceCounter"
		$opt78 = "RaiseException"
		$opt79 = "Read beyond end of file\tDisk full"
		$opt80 = "RegCloseKey"
		$opt81 = "RegOpenKeyExW"
		$opt82 = "RegQueryValueExW"
		$opt83 = "RegisterClass"
		$opt84 = "RemoveDirectoryW"
		$opt85 = "ResetEvent"
		$opt86 = "ResumeThread"
		$opt87 = "SafeArrayCreate"
		$opt88 = "SafeArrayGetLBound"
		$opt89 = "SafeArrayGetUBound"
		$opt90 = "SafeArrayPtrOfIndex"
		$opt91 = "SaveToFile"
		$opt92 = "SetDefaultDllDirectories"
		$opt93 = "SetDllDirectoryW"
		$opt94 = "SetEndOfFile"
		$opt95 = "SetErrorMode"
		$opt96 = "SetFilePointer"
		$opt97 = "SetLastError"
		$opt98 = "SetProcessDEPPolicy"
		$opt99 = "SetThreadLocale"
		$opt100 = "SetThreadPriority"
		$opt101 = "SetWindowLongW"
		$opt102 = "SizeofResource"
		$opt103 = "Stream write error"
		$opt104 = "SuspendThread"
		$opt105 = "SwitchToThread"
		$opt106 = "SysAllocStringLen"
		$opt107 = "SysFreeString"
		$opt108 = "SysReAllocStringLen"
		$opt109 = "TlsGetValue"
		$opt110 = "TlsSetValue"
		$opt111 = "TranslateMessage"
		$opt112 = "UnhandledExceptionFilter"
		$opt113 = "UnregisterClass"
		$opt114 = "VarBstrFromDate"
		$opt115 = "VarDateFromStr"
		$opt116 = "VariantChangeType"
		$opt117 = "VariantChangeTypeEx"
		$opt118 = "VariantClear"
		$opt119 = "VariantCopy"
		$opt120 = "VariantInit"
		$opt121 = "VerSetConditionMask"
		$opt122 = "VerifyVersionInfoW"
		$opt123 = "VirtualAlloc"
		$opt124 = "VirtualFree"
		$opt125 = "VirtualProtect"
		$opt126 = "VirtualQuery"
		$opt127 = "VirtualQueryEx"
		$opt128 = "WaitForSingleObject"
		$opt129 = "Wow64DisableWow64FsRedirection"
		$opt130 = "Wow64RevertWow64FsRedirection"
		$opt131 = "advapi32.dll"
		$opt132 = "apphelp.dll"
		$opt133 = "clbcatq.dll"
		$opt134 = "comctl32.dll"
		$opt135 = "cryptbase.dll"
		$opt136 = "dwmapi.dll"
		$opt137 = "kernel32.dll"
		$opt138 = "netapi32.dll"
		$opt139 = "ntmarta.dll"
		$opt140 = "oleacc.dll"
		$opt141 = "oleaut32.dll"
		$opt142 = "propsys.dll"
		$opt143 = "setupapi.dll"
		$opt144 = "shell32.dll"
		$opt145 = "user32.dll"
		$opt146 = "userenv.dll"
		$opt147 = "uxtheme.dll"
		$opt148 = "version.dll"

	condition:
		//require 50% of optional strings
		uint16(0) == 0x5A4D and filesize > 26932587 and filesize < 32917605 and all of ($req*) and 74 of ($opt*)
}
