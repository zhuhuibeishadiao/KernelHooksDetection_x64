#pragma once

NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeDetachProcess();

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY        InLoadOrderLinks;
	LIST_ENTRY        InMemoryOrderLinks;
	LIST_ENTRY        InInitializationOrderLinks;
	PVOID                        DllBase;
	PVOID                        EntryPoint;
	ULONG                        SizeOfImage;
	UNICODE_STRING        FullDllName;
	UNICODE_STRING         BaseDllName;
	//...剩下的成员省略
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
//
//typedef struct _LDR_DATA_TABLE_ENTRY32
//{
//	LIST_ENTRY32                InLoadOrderLinks;
//	LIST_ENTRY32                InMemoryOrderLinks;
//	LIST_ENTRY32                InInitializationOrderLinks;
//	ULONG                                DllBase;
//	ULONG                                EntryPoint;
//	ULONG                                SizeOfImage;
//	UNICODE_STRING32        FullDllName;
//	UNICODE_STRING32         BaseDllName;
//	ULONG                                Flags;
//	USHORT                                LoadCount;
//	USHORT                                TlsIndex;
//	//下面的省略
//} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;
PDRIVER_OBJECT g_DriverObject = NULL;

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe (native api)
	SYSTEM_SERVICE_TABLE win32k;    // win32k.sys   (gdi/user)
	SYSTEM_SERVICE_TABLE Table3;    // not used
	SYSTEM_SERVICE_TABLE Table4;    // not used
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#ifndef _MAX_PATH_
#define _MAX_PATH_
#define MAX_PATH 260
#endif // !_MAX_PATH

typedef struct _DRIVER_INFO {
	ULONG Count;
	WCHAR DriverPath[MAX_PATH];
	WCHAR DriverName[MAX_PATH];
}DRIVER_INFO, *PDRIVER_INFO;

typedef struct _DRIVER_PATCH_INFO {
	ULONG Count;
	ULONG64	PathchAddr;
	CHAR	CurrentCode[50];
	CHAR	OrigCode[50];
	WCHAR	DriverName[MAX_PATH];
	WCHAR	DriverPath[MAX_PATH];
}DRIVER_PATCH_INFO, *PDRIVER_PATCH_INFO;

PDRIVER_PATCH_INFO g_pDrvPatchInfo = NULL;
ULONG g_uPatchCount = 0;

DWORD64 g_SystemKernelModuleBase;
DWORD64 g_SystemKernelModuleSize;
WCHAR *g_SystemKernelFilePath;

extern PSHORT NtBuildNumber;

#ifdef AMD64
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable = NULL;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTableShadow = NULL;
#else
extern PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;
#endif

#ifdef AMD64
ULONGLONG GetKeServiceDescriptorTable64() //鬼佬的方法
{
	char KiSystemServiceStart_pattern[13] = "\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x25\xFF\x0F\x00\x00";	//睇唔明系么春特征码
	ULONGLONG CodeScanStart = (ULONGLONG)&_strnicmp;
	ULONGLONG CodeScanEnd = (ULONGLONG)&KdDebuggerNotPresent;
	ULONGLONG i, tbl_address, b;
	for (i = 0; i < CodeScanEnd - CodeScanStart; i++)
	{
		if (!memcmp((char*)(ULONGLONG)CodeScanStart + i, (char*)KiSystemServiceStart_pattern, 13))
		{
			for (b = 0; b < 50; b++)
			{
				tbl_address = ((ULONGLONG)CodeScanStart + i + b);
				if (*(USHORT*)((ULONGLONG)tbl_address) == (USHORT)0x8d4c)
					return ((LONGLONG)tbl_address + 7) + *(LONG*)(tbl_address + 3);
			}
		}
	}
	return 0;
}

ULONGLONG MyGetKeServiceDescriptorTable64() //我的方法
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1=0,b2=0,b3=0;
	ULONG templong=0;
	ULONGLONG addr=0;
	for(i=StartSearchAddress;i<EndSearchAddress;i++)
	{
		if( MmIsAddressValid(i) && MmIsAddressValid(i+1) && MmIsAddressValid(i+2) )
		{
			b1=*i;
			b2=*(i+1);
			b3=*(i+2);
			if( b1==0x4c && b2==0x8d && b3==0x15 ) //4c8d15
			{
				memcpy(&templong,i+3,4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}

BOOLEAN EnumDriver(PDRIVER_OBJECT pDriverObject ,PDRIVER_INFO *lpDriverInfo)
{
	ULONG Count = 0;
	PDRIVER_INFO pDrvInfo = NULL;
	//总是缺了上一个驱动的信息
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	//先向上枚举一个
	PLDR_DATA_TABLE_ENTRY firstentry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink;

	pDrvInfo = ExAllocatePool(NonPagedPool, sizeof(DRIVER_INFO) * 500);
	if (pDrvInfo == NULL)
		return FALSE;

	RtlZeroMemory(pDrvInfo, sizeof(DRIVER_INFO) * 500);
	//DbgPrint("%p\t%p\t%wZ\t%wZ\t\r\n", firstentry->DllBase, firstentry->EntryPoint, firstentry->BaseDllName, firstentry->FullDllName);

	RtlCopyMemory(pDrvInfo[0].DriverPath, firstentry->FullDllName.Buffer, firstentry->FullDllName.Length * 2);
	RtlCopyMemory(pDrvInfo[0].DriverName, firstentry->BaseDllName.Buffer, firstentry->BaseDllName.Length * 2);
	
	Count++;
	//再向下枚举所有
	entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	firstentry = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		// MmUserProbeAddress;
		if ((ULONG64)entry->EntryPoint > 0xFFFFF80000000000)
		{
			//DbgPrint("%p\t%p\t%wZ\t%wZ\t\r\n", entry->DllBase, entry->EntryPoint, entry->BaseDllName, entry->FullDllName);
			RtlCopyMemory(pDrvInfo[Count].DriverPath, entry->FullDllName.Buffer, entry->FullDllName.Length * 2);
			RtlCopyMemory(pDrvInfo[Count].DriverName, entry->BaseDllName.Buffer, entry->BaseDllName.Length * 2);
			Count++;
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	if (Count - 1 == 0)
		return FALSE;

	pDrvInfo[0].Count = Count;
	*lpDriverInfo = pDrvInfo;
	return TRUE;
}


ULONGLONG GetKeServiceDescriptorTableShadow64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i<EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d) //4c8d1d
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}
#endif

PVOID GetFunctionAddressInSSDT(ULONG id)
{
	PULONG ServiceTableBase = NULL;
#ifdef AMD64
	LONG dwtmp = 0;
	if (!KeServiceDescriptorTable)
		KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64();
	if (!KeServiceDescriptorTable)
		return NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	if (NtBuildNumber < 6000)
		dwtmp = dwtmp & 0xfffffff0;
	else
		dwtmp = dwtmp >> 4;
	return (PVOID)((LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase);
#else
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	return (PVOID)(ServiceTableBase[id]);
#endif
}

VOID WcharToChar(__in WCHAR *wzFuncName, __out CHAR *FuncName)
{
	UNICODE_STRING UnicodeFuncName;
	ANSI_STRING AnsiFuncName;

	RtlInitUnicodeString(&UnicodeFuncName, wzFuncName);
	if (RtlUnicodeStringToAnsiString(&AnsiFuncName, &UnicodeFuncName, TRUE) == STATUS_SUCCESS) {
		memcpy(FuncName, AnsiFuncName.Buffer, AnsiFuncName.Length);
		RtlFreeAnsiString(&AnsiFuncName);
	}
}
/*
小写
*/
PVOID GetKernelModuleBase(PDRIVER_OBJECT DriverObject, char *KernelModuleName)
{
	PLDR_DATA_TABLE_ENTRY LdrDataTable;

	CHAR lpModule[260];
	//WCHAR lpSysMode[260];

	__try
	{
		LdrDataTable = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		do
		{
			if (LdrDataTable->BaseDllName.Length>0 && LdrDataTable->BaseDllName.Buffer != NULL)
			{
				if (MmIsAddressValid(&LdrDataTable->BaseDllName.Buffer[LdrDataTable->BaseDllName.Length / 2 - 1]))
				{
					//DbgPrint("Module:%ws\n", LdrDataTable->BaseDllName.Buffer);
					memset(lpModule, 0, sizeof(lpModule));

					/*memset(lpModule, 0, sizeof(lpModule));
					memset(lpSysMode, 0, sizeof(lpSysMode));


					RtlCopyMemory(lpSysMode, LdrDataTable->BaseDllName.Buffer, LdrDataTable->BaseDllName.Length * 2);
					CharToWchar(KernelModuleName, lpModule);

					if(wcsstr(lpSysMode, lpModule))
					{
					return LdrDataTable->DllBase;
					}*/
					WcharToChar(LdrDataTable->BaseDllName.Buffer, lpModule);

					_strlwr(lpModule);
					if (_stricmp(lpModule, KernelModuleName) == 0)
					{
						return LdrDataTable->DllBase;
					}
				}
			}
			LdrDataTable = (PLDR_DATA_TABLE_ENTRY)LdrDataTable->InLoadOrderLinks.Flink;

		} while ((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection != LdrDataTable&&LdrDataTable != NULL);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	}
	return NULL;
}

PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader_RE(
	PVOID Base
)
{
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	(VOID)RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, Base, 0, &NtHeaders);
	return NtHeaders;
}

PVOID
EasyDebugger_RtlImageDirectoryEntryToData(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size
)
{
	PIMAGE_NT_HEADERS NtHeaders;
	if (LDR_IS_DATAFILE(Base)) {
		Base = LDR_DATAFILE_TO_VIEW(Base);
		MappedAsImage = FALSE;
	}
	NtHeaders = RtlImageNtHeader_RE(Base);
	if (!NtHeaders)
		return NULL;
	if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return (RtlpImageDirectoryEntryToData32(Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			(PIMAGE_NT_HEADERS32)NtHeaders));
	}
	else if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		return (RtlpImageDirectoryEntryToData64(Base,
			MappedAsImage,
			DirectoryEntry,
			Size,
			(PIMAGE_NT_HEADERS64)NtHeaders));
	}
	else {
		return (NULL);
	}
}

BOOLEAN GetSystemKernelModuleInfo(
	__in  PDRIVER_OBJECT DriverObject,
	__out WCHAR **SystemKernelModulePath,
	__out DWORD64 *mSystemKernelModuleBase,
	__out DWORD64 *mSystemKernelModuleSize,
	__in BOOLEAN isNtSysmodule,
	__in WCHAR* szModueNama
)
{
	PLDR_DATA_TABLE_ENTRY LdrDataTable;
	BOOLEAN bRetOK = FALSE;
	int i = 0;
	WCHAR wzKernelName[4][100] = { L"ntkrnlpa.exe", L"ntoskrnl.exe", L"ntkrnlmp.exe", L"ntkrpamp.exe" };
	UNICODE_STRING UnicodeKernelString;

	__try
	{
		*SystemKernelModulePath = (WCHAR *)ExAllocatePool(NonPagedPool, 260 * 2);
		if (*SystemKernelModulePath == NULL)
		{
			*mSystemKernelModuleBase = 0;
			*mSystemKernelModuleSize = 0;
			return FALSE;
		}
		memset(*SystemKernelModulePath, 0, 260 * 2);

		LdrDataTable = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
		do
		{
			if (LdrDataTable->BaseDllName.Length>0 && LdrDataTable->BaseDllName.Buffer != NULL)
			{
				if (MmIsAddressValid(&LdrDataTable->BaseDllName.Buffer[LdrDataTable->BaseDllName.Length / 2 - 1]))
				{
					if (!isNtSysmodule)
					{
						if (wcsstr(LdrDataTable->BaseDllName.Buffer, szModueNama))
						{
							DbgPrint("Found Module:%ws base:%p size:%X\n", LdrDataTable->BaseDllName.Buffer, LdrDataTable->DllBase, LdrDataTable->SizeOfImage);
							*mSystemKernelModuleBase = (DWORD64)LdrDataTable->DllBase;
							*mSystemKernelModuleSize = (DWORD64)LdrDataTable->SizeOfImage;
							memcpy(*SystemKernelModulePath, LdrDataTable->FullDllName.Buffer, LdrDataTable->FullDllName.Length);
							bRetOK = TRUE;
							break;
						}
					}
					else
					{
						for (i = 0; i<3; i++)
						{
							RtlInitUnicodeString(&UnicodeKernelString, wzKernelName[i]);
							if (RtlCompareUnicodeString(&LdrDataTable->BaseDllName, &UnicodeKernelString, TRUE) == 0)
							{

								DbgPrint("Found KernelModule:%ws base:%p size:%X\n", LdrDataTable->BaseDllName.Buffer, LdrDataTable->DllBase, LdrDataTable->SizeOfImage);

								*mSystemKernelModuleBase = (DWORD64)LdrDataTable->DllBase;
								*mSystemKernelModuleSize = (DWORD64)LdrDataTable->SizeOfImage;
								memcpy(*SystemKernelModulePath, LdrDataTable->FullDllName.Buffer, LdrDataTable->FullDllName.Length);
								bRetOK = TRUE;
								break;
							}
						}
					}

				}
			}
			LdrDataTable = (PLDR_DATA_TABLE_ENTRY)LdrDataTable->InLoadOrderLinks.Flink;

		} while ((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection != LdrDataTable&&LdrDataTable != NULL);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
	}
	return bRetOK;
}

PVOID
MiFindExportedRoutine(
	IN PVOID DllBase,
	int ByName,
	IN char *RoutineName,
	DWORD64 Ordinal
)

/*++

Routine Description:

This function searches the argument module looking for the requested
exported function name.

Arguments:

DllBase - Supplies the base address of the requested module.

AnsiImageRoutineName - Supplies the ANSI routine name being searched for.

Return Value:

The virtual address of the requested routine or NULL if not found.

--*/

{
	USHORT OrdinalNumber;
	PULONG NameTableBase;
	PUSHORT NameOrdinalTableBase;
	PULONG AddressTableBase;
	PULONG Addr;
	LONG High;
	LONG Low;
	LONG Middle;
	LONG Result;
	ULONG ExportSize;
	PVOID FunctionAddress;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

	PAGED_CODE();

	ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)EasyDebugger_RtlImageDirectoryEntryToData(
		DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (ExportDirectory == NULL) {
		return NULL;
	}

	//
	// Initialize the pointer to the array of RVA-based ansi export strings.
	//

	NameTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNames);

	//
	// Initialize the pointer to the array of USHORT ordinal numbers.
	//

	NameOrdinalTableBase = (PUSHORT)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfNameOrdinals);

	AddressTableBase = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);

	if (!ByName)
	{
		return (PVOID)AddressTableBase[Ordinal];
	}

	//
	// Lookup the desired name in the name table using a binary search.
	//

	Low = 0;
	Middle = 0;
	High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low) {

		//
		// Compute the next probe index and compare the import name
		// with the export name entry.
		//

		Middle = (Low + High) >> 1;

		Result = strcmp(RoutineName,
			(PCHAR)DllBase + NameTableBase[Middle]);

		if (Result < 0) {
			High = Middle - 1;
		}
		else if (Result > 0) {
			Low = Middle + 1;
		}
		else {
			break;
		}
	}
	//
	// If the high index is less than the low index, then a matching
	// table entry was not found. Otherwise, get the ordinal number
	// from the ordinal table.
	//

	if (High < Low) {
		return NULL;
	}

	OrdinalNumber = NameOrdinalTableBase[Middle];

	//
	// If the OrdinalNumber is not within the Export Address Table,
	// then this image does not implement the function.  Return not found.
	//

	if ((ULONG)OrdinalNumber >= ExportDirectory->NumberOfFunctions) {
		return NULL;
	}

	//
	// Index into the array of RVA export addresses by ordinal number.
	//

	Addr = (PULONG)((PCHAR)DllBase + (ULONG)ExportDirectory->AddressOfFunctions);

	FunctionAddress = (PVOID)((PCHAR)DllBase + Addr[OrdinalNumber]);

	//
	// Forwarders are not used by the kernel and HAL to each other.
	//

	// 	ASSERT ((FunctionAddress <= (PVOID)ExportDirectory) ||
	// 		(FunctionAddress >= (PVOID)((PCHAR)ExportDirectory + ExportSize)));

	if ((ULONG_PTR)FunctionAddress > (ULONG_PTR)ExportDirectory &&
		(ULONG_PTR)FunctionAddress < ((ULONG_PTR)ExportDirectory + ExportSize)) {
		FunctionAddress = NULL;
	}
	return FunctionAddress;
}

BOOLEAN InsertOriginalFirstThunk(DWORD64 ImageBase, DWORD64 ExistImageBase, PIMAGE_THUNK_DATA FirstThunk)
{
	DWORD64 Offset;
	PIMAGE_THUNK_DATA OriginalFirstThunk;
	Offset = (DWORD64)FirstThunk - ImageBase;
	OriginalFirstThunk = (PIMAGE_THUNK_DATA)(ExistImageBase + Offset);
	while (OriginalFirstThunk->u1.Function)
	{

		//DbgPrint("Fuction Address:%X\n", OriginalFirstThunk->u1.Function);
		FirstThunk->u1.Function = OriginalFirstThunk->u1.Function;
		OriginalFirstThunk++;
		FirstThunk++;
	}
	return TRUE;

}

BOOLEAN FixImportTable(unsigned char *ImageBase, DWORD64 ExistImageBase, PDRIVER_OBJECT DriverObject)
{
	PIMAGE_IMPORT_DESCRIPTOR ImageImportDescriptor = NULL;
	PIMAGE_THUNK_DATA ImageThunkData, FirstThunk;
	PIMAGE_IMPORT_BY_NAME ImortByName;
	DWORD64 ImportSize;
	PVOID ModuleBase;
	char ModuleName[260];
	DWORD64 FunctionAddress;

	ImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)EasyDebugger_RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, (PULONG)&ImportSize);
	if (ImageImportDescriptor == NULL)
	{
		return FALSE;
	}
	while (ImageImportDescriptor->OriginalFirstThunk&&ImageImportDescriptor->Name)
	{
		strcpy(ModuleName, (char*)(ImageBase + ImageImportDescriptor->Name));

		//DbgPrint("ModuleName:%s\n", ModuleName);

		_strlwr(ModuleName);
		//ntoskrnl.exe(NTKRNLPA.exe、ntkrnlmp.exe、ntkrpamp.exe)：
		if (_stricmp(ModuleName, "ntkrnlpa.exe") == 0 ||
			_stricmp(ModuleName, "ntoskrnl.exe") == 0 ||
			_stricmp(ModuleName, "ntkrnlmp.exe") == 0 ||
			_stricmp(ModuleName, "ntkrpamp.exe") == 0)
		{
			//set ntos base
			ModuleBase = (PVOID)g_SystemKernelModuleBase;

		}
		else
		{
			ModuleBase = GetKernelModuleBase(DriverObject, ModuleName);

		}
		if (ModuleBase == NULL)
		{

			DbgPrint("can't find module:%s\n", ModuleName);

			FirstThunk = (PIMAGE_THUNK_DATA)(ImageBase + ImageImportDescriptor->FirstThunk);
			InsertOriginalFirstThunk((DWORD64)ImageBase, ExistImageBase, FirstThunk);
			ImageImportDescriptor++;
			continue;
		}
		ImageThunkData = (PIMAGE_THUNK_DATA)(ImageBase + ImageImportDescriptor->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)(ImageBase + ImageImportDescriptor->FirstThunk);
		while (ImageThunkData->u1.Ordinal)
		{
			//序号导入
			if (IMAGE_SNAP_BY_ORDINAL32(ImageThunkData->u1.Ordinal))
			{
				FunctionAddress = (DWORD64)MiFindExportedRoutine(ModuleBase, FALSE, NULL, ImageThunkData->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
				if (FunctionAddress == 0)
				{

					DbgPrint("can't find funcion Index %d \n", ImageThunkData->u1.Ordinal & ~IMAGE_ORDINAL_FLAG32);
					break;
				}
				FirstThunk->u1.Function = FunctionAddress;
			}
			//函数名导入
			else
			{
				//
				ImortByName = (PIMAGE_IMPORT_BY_NAME)(ImageBase + ImageThunkData->u1.AddressOfData);
				FunctionAddress = (DWORD64)MiFindExportedRoutine(ModuleBase, TRUE, ImortByName->Name, 0);
				if (FunctionAddress == 0)
				{

					DbgPrint(("can't Funcion Name:%s\n", ImortByName->Name));
					break;
				}
				FirstThunk->u1.Function = FunctionAddress;
			}
			FirstThunk++;
			ImageThunkData++;
		}
		ImageImportDescriptor++;
	}
	return TRUE;
}

/*
根据Load的文件信息得到原始模块的信息
*/
BOOLEAN CalcCheckInfo(_In_ PKERNEL_CHECK_INFO* pLoadCheckInfo, __in_opt PKERNEL_CHECK_INFO *lpRealCheckInfo, _In_ char* ModuleName, _In_  ULONG64 uLoadModuleBase, ULONG64* lpRealSysBase)
{
	/*
	1. 获取Load模块的原始模块基址
	2. 计算偏移即可
	*/
	ULONG64	uBase = 0;
	PKERNEL_CHECK_INFO pRealCheckInfo = NULL;
	PKERNEL_CHECK_INFO pMemCheckInfo = NULL;

	if (pLoadCheckInfo == NULL || uLoadModuleBase == 0)
	{
		return FALSE;
	}

	pMemCheckInfo = *pLoadCheckInfo;

	pRealCheckInfo = ExAllocatePool(NonPagedPool, sizeof(KERNEL_CHECK_INFO) * 50);

	if (pRealCheckInfo == NULL)
		return FALSE;

	uBase = (ULONG64)GetKernelModuleBase(g_DriverObject, ModuleName);

	if (uBase == 0)
	{
		ExFreePool(pRealCheckInfo);
		return FALSE;
	}

	ULONG LoadCheckCount = 0;
	LoadCheckCount = pMemCheckInfo[0].Count;


	/*
	真实模块Check地址 = Load模块Check地址 - Load模块Base + 真实模块Base;
	*/
	for (size_t i = 0; i < LoadCheckCount; i++)
	{
		pRealCheckInfo[i].StartAddr = pMemCheckInfo[i].StartAddr - uLoadModuleBase + uBase;
		pRealCheckInfo[i].EndAddr = pMemCheckInfo[i].EndAddr - uLoadModuleBase + uBase;
	}

	pRealCheckInfo[0].Count = LoadCheckCount;
	*lpRealCheckInfo = pRealCheckInfo;
	*lpRealSysBase = uBase;
	return TRUE;
}

PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS eprocess = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Pid, &eprocess)))
		return eprocess;
	else
		return NULL;
}

PEPROCESS GetGuiProcess(BOOLEAN bTry)
{
	ULONG i = 0;
	PEPROCESS eproc = NULL;
	for (i = 4; i<262144; i = i + 4)
	{
		eproc = LookupProcess((HANDLE)i);
		if (eproc != NULL)
		{
			ObDereferenceObject(eproc);
			CHAR *Name = (CHAR*)PsGetProcessImageFileName(eproc);
			/*if (!_strnicmp("explorer.exe", Name, strlen("explorer.exe")))
			{
			DbgPrint("EPROCESS=%p PID=%ld,Name=%s\n", eproc, PsGetProcessId(eproc), PsGetProcessImageFileName(eproc));
			return eproc;
			}
			else */
			if (bTry)
			{
				if (!_strnicmp("explorer.exe", Name, strlen("explorer.exe")))
				{
					//DbgPrint("EPROCESS=%p PID=%ld,Name=%s\n", eproc, PsGetProcessId(eproc), PsGetProcessImageFileName(eproc));
					return eproc;
				}
			}
			else if (!_strnicmp("csrss.exe", Name, strlen("csrss.exe")))
			{
				//DbgPrint("EPROCESS=%p PID=%ld,Name=%s\n", eproc, PsGetProcessId(eproc), PsGetProcessImageFileName(eproc));
				return eproc;
			}
		}
	}
	return NULL;
}

void PrintBytes(char *DescriptionString, PUCHAR ba, INT Length)
{
	KdPrint(("%s", DescriptionString));
	for (INT i = 0; i<Length; i++)
	{
		KdPrint(("%02x ", ba[i]));
	}
	KdPrint(("\n"));
}

NTSTATUS CheckTest(WCHAR* SysModulePath, char* SysName, WCHAR* wSysName)
{
	PVOID lpLoadMem = NULL;
	ULONG64 uRealSysBase = 0;
	CHAR	*CurrentCode = NULL;
	CHAR	*OrgCode = NULL;
	PEPROCESS GuiProcess = NULL;
	PKERNEL_CHECK_INFO pCheckInfo = NULL;
	PKERNEL_CHECK_INFO pRealCheckInfo = NULL;

	CurrentCode = (CHAR*)ExAllocatePool(NonPagedPool, 50);
	OrgCode = (CHAR*)ExAllocatePool(NonPagedPool ,50);

	if (CurrentCode == NULL || OrgCode == NULL)
		return STATUS_UNSUCCESSFUL;

	RtlZeroMemory(CurrentCode , 50);
	RtlZeroMemory(OrgCode, 50);

	GuiProcess = GetGuiProcess(FALSE);

	if (GuiProcess == NULL)
		GuiProcess = GetGuiProcess(TRUE);

	if (GuiProcess == NULL)
		return STATUS_UNSUCCESSFUL;

	//DbgPrint("GuiProcess:0x%p\n", GuiProcess);
	// L"\\SystemRoot\\system32\\win32k.sys"
	if (NT_SUCCESS(loadFileToMem(SysModulePath, &lpLoadMem, &pCheckInfo)))
	{
		//DbgPrint("%s:0x%p\n", SysName, lpLoadMem);

		ULONG Count = 0;

		Count = pCheckInfo[0].Count;

		/*DbgPrint("--------------LoadMemCheckInfo--------------\r\n");

		DbgPrint("Count:%d\r\n", Count);
		for (size_t i = 0; i < Count; i++)
		{
			DbgPrint(
				"StartAddress:0x%p\r\n"
				"EndAddress:0x%p\r\n"
				, pCheckInfo[i].StartAddr
				, pCheckInfo[i].EndAddr
			);
		}*/
		//DbgPrint("--------------LoadMemCheckEnd--------------\r\n\n");

		if (!CalcCheckInfo(&pCheckInfo, &pRealCheckInfo, SysName, (ULONG64)lpLoadMem, &uRealSysBase))
		{
			ExFreePool(pCheckInfo);
			ExFreePool(lpLoadMem);
			//DbgPrint("CalcCheckInfo return false\r\n");
			return STATUS_UNSUCCESSFUL;
		}

		//DbgPrint("%s:0x%p\n", SysName, uRealSysBase);
		//DbgPrint("--------------RealCheckInfo--------------\r\n");
		Count = pRealCheckInfo[0].Count;
		//DbgPrint("Count:%d\r\n", Count);
		/*for (size_t i = 0; i < Count; i++)
		{
			DbgPrint(
				"StartAddress:0x%p\r\n"
				"EndAddress:0x%p\r\n"
				, pRealCheckInfo[i].StartAddr
				, pRealCheckInfo[i].EndAddr
			);
		}
		DbgPrint("--------------RealCheckEnd--------------\r\n\n");*/

		
		PCHAR pLoadCheckAddr = NULL;
		PCHAR pRealCheckAddr = NULL;
		ULONG64 W32pServiceTableAddr = 0;
		ULONG64	KiServiceTable = 0;
		LONG	uRealLen = 0;
		LONG	uLoadLen = 0;
		ULONG	uCurrentModulePatchCount = 0;
		if (strstr(SysName, "win32k"))
		{
			W32pServiceTableAddr = (ULONG64)KeServiceDescriptorTableShadow->ServiceTableBase;//pCheckInfo[0].StartAddr + 0x00000000000d0f00;
		}

		if (strstr(SysName, "ntkrnlpa") || strstr(SysName, "ntoskrnl") || strstr(SysName, "ntkrnlmp") || strstr(SysName, "ntkrpamp"))
		{
			KiServiceTable = (ULONG64)KeServiceDescriptorTable->ServiceTableBase;
		}

		if (strstr(SysName, "ks.sys"))
			goto ExitEx;
		//DbgPrint("--------------Start Check Kernel--------------\r\n");
		KeAttachProcess(GuiProcess);

		//DbgPrint("\nFixImp:%s:0x%p\n", SysName, uRealSysBase);
		// 修复导入表
		if (!FixImportTable(lpLoadMem, uRealSysBase, g_DriverObject))
		{
			DbgPrint("FixImportTable faild !\n");
		}

		for (size_t i = 0; i < Count; i++)
		{
			//DbgPrint("Current:%d\n", i);
			//0x2142
			//CodeSize = pCheckInfo[i].EndAddr - pCheckInfo[i].StartAddr;
			pLoadCheckAddr = (PCHAR)pCheckInfo[i].StartAddr;
			pRealCheckAddr = (PCHAR)pRealCheckInfo[i].StartAddr;

			/*DbgPrint(
				"Check:pLoadCheckAddr0x%p\r\n"
				"Check:pRealCheckAddr0x%p\r\n"
				,pLoadCheckAddr
				,pRealCheckAddr
			);*/
			for (;(ULONG64)pLoadCheckAddr < pCheckInfo[i].EndAddr;)
			{
				if (!MmIsAddressValid(pLoadCheckAddr) || !MmIsAddressValid(pRealCheckAddr))
				{
					pLoadCheckAddr++;
					pRealCheckAddr++;
					continue;
				}
					

				if (*pLoadCheckAddr != *pRealCheckAddr)
				{
					if (pRealCheckAddr == W32pServiceTableAddr)
					{
						// 跳过SSSDT (W32pServiceTableAddr)
						pLoadCheckAddr += 0x2142;
						pRealCheckAddr += 0x2142;
						continue;
					}

					if (pRealCheckAddr == KiServiceTable)
					{
						// 跳过SSDT (KiServiceTable)
						pLoadCheckAddr += 0xe40;
						pRealCheckAddr += 0xe40;
						continue;
					}

					uRealLen = LDE(pRealCheckAddr, 64);
					uLoadLen = LDE(pRealCheckAddr, 64);
					/*DbgPrint(
						"RealCodeLen:%d\r\n"
						"LoadCodeLen:%d\r\n"
						, uRealLen
						, uLoadLen
					);*/

					if (MmIsAddressValid(pLoadCheckAddr + 15) && MmIsAddressValid(pRealCheckAddr + 15))
					{
						RtlCopyMemory(CurrentCode, pRealCheckAddr, 15);
						RtlCopyMemory(OrgCode, pLoadCheckAddr, 15);
						
						//if (pLoadCheckAddr - 0x10 == pLastCheckAddr)
						//{
						//	/*uEqualCount++;
						//	if (uEqualCount > 1)
						//	{
						//		DbgPrint("Not Code!\r\n");
						//		pLoadCheckAddr += 0x1d4;
						//		pRealCheckAddr += 0x1d4;
						//		RtlZeroMemory(CurrentCode, 50);
						//		RtlZeroMemory(OrgCode, 50);
						//		uEqualCount = 0;
						//		pLastCheckAddr = pLoadCheckAddr;
						//		continue;
						//	}*/
						//	

						//	DbgPrint("Not Code!\r\n");
						//	pLoadCheckAddr += 0x1d4;
						//	pRealCheckAddr += 0x1d4;
						//	RtlZeroMemory(CurrentCode, 50);
						//	RtlZeroMemory(OrgCode, 50);
						//	pLastCheckAddr = pLoadCheckAddr;
						//	continue;
						//}
						// 不可能有 1字节 3字节 4字节的hook 去除 否则都是Patch
						if (uRealLen == -1 || uLoadLen == -1 || uLoadLen == 1 || uRealLen == 1 || uLoadLen == 3 || uRealLen == 3 || uLoadLen == 4 || uRealLen == 4)
						{
							//DbgPrint("Not Code!\r\n");
							pLoadCheckAddr += 0x1d4;
							pRealCheckAddr += 0x1d4;
							RtlZeroMemory(CurrentCode, 50);
							RtlZeroMemory(OrgCode, 50);
							//pLastCheckAddr = pLoadCheckAddr;
							continue;
						}

						//DbgPrint("LoadCheckAddress0x%p\r\n", pLoadCheckAddr);
						//DbgPrint("RealCheckAddress0x%p\r\n", pRealCheckAddr);

						//PrintBytes("CurrentCode:", CurrentCode, 15);
						//PrintBytes("OrgCode:", OrgCode, 15);
						
						//pLastCheckAddr = pLoadCheckAddr;

						g_pDrvPatchInfo[g_uPatchCount].PathchAddr = pRealCheckAddr;
						
						RtlCopyMemory(g_pDrvPatchInfo[g_uPatchCount].CurrentCode, CurrentCode, 15);
						RtlCopyMemory(g_pDrvPatchInfo[g_uPatchCount].OrigCode, OrgCode, 15);

						RtlZeroMemory(g_pDrvPatchInfo[g_uPatchCount].DriverName, MAX_PATH * 2);
						RtlZeroMemory(g_pDrvPatchInfo[g_uPatchCount].DriverPath, MAX_PATH * 2);

						RtlCopyMemory(g_pDrvPatchInfo[g_uPatchCount].DriverName, wSysName, wcslen(wSysName) * 2);
						RtlCopyMemory(g_pDrvPatchInfo[g_uPatchCount].DriverPath, SysModulePath, wcslen(SysModulePath) * 2);

						// 一般是变形壳
						if (uCurrentModulePatchCount > 100)
						{
							g_uPatchCount = g_uPatchCount - uCurrentModulePatchCount;
							goto Exit;
						}
						uCurrentModulePatchCount++;
						g_uPatchCount++;
						if (g_uPatchCount > 500)
						{
							g_uPatchCount = 500;
							goto Exit;
						}
							
						RtlZeroMemory(CurrentCode, 50);
						RtlZeroMemory(OrgCode, 50);
					}
					else
					{
						DbgPrint("Find Hook Address, but buff to long\r\n");
					}
					pLoadCheckAddr += 15;
					pRealCheckAddr += 15;
				}
				else
				{
					pLoadCheckAddr++;
					pRealCheckAddr++;
				}
			}
		}
		Exit:
		KeDetachProcess();
		ExitEx:
		//DbgPrint("--------------End Check Kernel--------------\r\n\n");
		ExFreePool(pCheckInfo);
		ExFreePool(lpLoadMem);
		ExFreePool(CurrentCode);
		ExFreePool(OrgCode);
		pCheckInfo = NULL;
		lpLoadMem = NULL;
		CurrentCode = NULL;
		OrgCode = NULL;

		return STATUS_SUCCESS;
	}

	return STATUS_UNSUCCESSFUL;
}
