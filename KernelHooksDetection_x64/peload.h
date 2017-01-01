#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define RetMin(a,b)	(a<b?a:b)
#define IMAGE_REL_BASED_SECTION               6
#define IMAGE_REL_BASED_REL32                 7

//////////////////////////////////////////////////////////////////////////

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct
{
	ULONG ModuleCount;
	SYSTEM_MODULE Module[0];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

#define RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK (0x00000001)
NTSTATUS
NTAPI
RtlImageNtHeaderEx(
	ULONG Flags,
	PVOID Base,
	ULONG64 Size,
	OUT PIMAGE_NT_HEADERS * OutHeaders
)

/*++

Routine Description:

This function returns the address of the NT Header.

This function is a bit complicated.
It is this way because RtlImageNtHeader that it replaces was hard to understand,
and this function retains compatibility with RtlImageNtHeader.

RtlImageNtHeader was #ifed such as to act different in each of the three
boot loader, kernel, usermode flavors.

boot loader -- no exception handling
usermode -- limit msdos header to 256meg, catch any exception accessing the msdos-header
or the pe header
kernel -- don't cross user/kernel boundary, don't catch the exceptions,
no 256meg limit

Arguments:

Flags - RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK -- don't be so picky
about the image, for compatibility with RtlImageNtHeader
Base - Supplies the base of the image.
Size - The size of the view, usually larger than the size of the file on disk.
This is available from NtMapViewOfSection but not from MapViewOfFile.
OutHeaders -

Return Value:

STATUS_SUCCESS -- everything ok
STATUS_INVALID_IMAGE_FORMAT -- bad filesize or signature value
STATUS_INVALID_PARAMETER -- bad parameters

--*/

{
	PIMAGE_NT_HEADERS NtHeaders = 0;
	ULONG e_lfanew = 0;
	BOOLEAN RangeCheck = 0;
	NTSTATUS Status = 0;
	const ULONG ValidFlags =
		RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK;

	if (OutHeaders != NULL) {
		*OutHeaders = NULL;
	}
	if (OutHeaders == NULL) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	if ((Flags & ~ValidFlags) != 0) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}
	if (Base == NULL || Base == (PVOID)(LONG_PTR)-1) {
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	if (!MmIsAddressValid(Base))
	{
		DbgPrint("Base is no Valid !\n");
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	RangeCheck = ((Flags & RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK) == 0);
	if (RangeCheck) {
		if (Size < sizeof(IMAGE_DOS_HEADER)) {
			Status = STATUS_INVALID_IMAGE_FORMAT;
			goto Exit;
		}
	}

	//
	// Exception handling is not available in the boot loader, and exceptions
	// were not historically caught here in kernel mode. Drivers are considered
	// trusted, so we can't get an exception here due to a bad file, but we
	// could take an inpage error.
	//
#define EXIT goto Exit
	if (((PIMAGE_DOS_HEADER)Base)->e_magic != IMAGE_DOS_SIGNATURE) {
		Status = STATUS_INVALID_IMAGE_FORMAT;
		EXIT;
	}
	e_lfanew = ((PIMAGE_DOS_HEADER)Base)->e_lfanew;
	if (RangeCheck) {
		if (e_lfanew >= Size
#define SIZEOF_PE_SIGNATURE 4
			|| e_lfanew >= (MAXULONG - SIZEOF_PE_SIGNATURE - sizeof(IMAGE_FILE_HEADER))
			|| (e_lfanew + SIZEOF_PE_SIGNATURE + sizeof(IMAGE_FILE_HEADER)) >= Size
			) {
			Status = STATUS_INVALID_IMAGE_FORMAT;
			EXIT;
		}
	}

	NtHeaders = (PIMAGE_NT_HEADERS)((PCHAR)Base + e_lfanew);

	//
	// In kernelmode, do not cross from usermode address to kernelmode address.
	//
	if (Base < MM_HIGHEST_USER_ADDRESS) {
		if ((PVOID)NtHeaders >= MM_HIGHEST_USER_ADDRESS) {
			Status = STATUS_INVALID_IMAGE_FORMAT;
			EXIT;
		}
		//
		// Note that this check is slightly overeager since IMAGE_NT_HEADERS has
		// a builtin array of data_directories that may be larger than the image
		// actually has. A better check would be to add FileHeader.SizeOfOptionalHeader,
		// after ensuring that the FileHeader does not cross the u/k boundary.
		//
		if ((PVOID)((PCHAR)NtHeaders + sizeof(IMAGE_NT_HEADERS)) >= MM_HIGHEST_USER_ADDRESS) {
			Status = STATUS_INVALID_IMAGE_FORMAT;
			EXIT;
		}
	}

	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		Status = STATUS_INVALID_IMAGE_FORMAT;
		EXIT;
	}
	Status = STATUS_SUCCESS;

Exit:
	if (NT_SUCCESS(Status)) {
		*OutHeaders = NtHeaders;
	}
	return Status;
}
#undef EXIT

PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	PVOID Base
)
{
	PIMAGE_NT_HEADERS NtHeaders = NULL;
	(VOID)RtlImageNtHeaderEx(RTL_IMAGE_NT_HEADER_EX_FLAG_NO_RANGE_CHECK, Base, 0, &NtHeaders);
	return NtHeaders;
}

PIMAGE_SECTION_HEADER
RtlSectionTableFromVirtualAddress(
	IN PIMAGE_NT_HEADERS NtHeaders,
	IN PVOID Base,
	IN ULONG Address
)

/*++

Routine Description:

This function locates a VirtualAddress within the image header
of a file that is mapped as a file and returns a pointer to the
section table entry for that virtual address

Arguments:

NtHeaders - Supplies the pointer to the image or data file.

Base - Supplies the base of the image or data file.

Address - Supplies the virtual address to locate.

Return Value:

NULL - The file does not contain data for the specified directory entry.

NON-NULL - Returns the pointer of the section entry containing the data.

--*/

{
	ULONG i;
	PIMAGE_SECTION_HEADER NtSection;

	NtSection = IMAGE_FIRST_SECTION(NtHeaders);
	for (i = 0; i<NtHeaders->FileHeader.NumberOfSections; i++) {
		if ((ULONG)Address >= NtSection->VirtualAddress &&
			(ULONG)Address < NtSection->VirtualAddress + NtSection->SizeOfRawData
			) {
			return NtSection;
		}
		++NtSection;
	}

	return NULL;
}

PVOID
RtlAddressInSectionTable(
	IN PIMAGE_NT_HEADERS NtHeaders,
	IN PVOID Base,
	IN ULONG Address
)

/*++

Routine Description:

This function locates a VirtualAddress within the image header
of a file that is mapped as a file and returns the seek address
of the data the Directory describes.

Arguments:

NtHeaders - Supplies the pointer to the image or data file.

Base - Supplies the base of the image or data file.

Address - Supplies the virtual address to locate.

Return Value:

NULL - The file does not contain data for the specified directory entry.

NON-NULL - Returns the address of the raw data the directory describes.

--*/

{
	PIMAGE_SECTION_HEADER NtSection;

	NtSection = RtlSectionTableFromVirtualAddress(NtHeaders,
		Base,
		Address
	);
	if (NtSection != NULL) {
		return(((PCHAR)Base + ((ULONG_PTR)Address - NtSection->VirtualAddress) + NtSection->PointerToRawData));
	}
	else {
		return(NULL);
	}
}

PVOID
RtlpImageDirectoryEntryToData32(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size,
	PIMAGE_NT_HEADERS32 NtHeaders
)
{
	ULONG DirectoryAddress;

	if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
		return(NULL);
	}

	if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
		return(NULL);
	}

	if (Base < MM_HIGHEST_USER_ADDRESS) {
		if ((PVOID)((PCHAR)Base + DirectoryAddress) >= MM_HIGHEST_USER_ADDRESS) {
			return(NULL);
		}
	}

	*Size = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size;
	if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
		return((PVOID)((PCHAR)Base + DirectoryAddress));
	}

	return(RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress));
}

PVOID
RtlpImageDirectoryEntryToData64(
	IN PVOID Base,
	IN BOOLEAN MappedAsImage,
	IN USHORT DirectoryEntry,
	OUT PULONG Size,
	PIMAGE_NT_HEADERS64 NtHeaders
)
{
	ULONG DirectoryAddress;

	if (DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {
		return(NULL);
	}

	if (!(DirectoryAddress = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress)) {
		return(NULL);
	}

	if (Base < MM_HIGHEST_USER_ADDRESS) {
		if ((PVOID)((PCHAR)Base + DirectoryAddress) >= MM_HIGHEST_USER_ADDRESS) {
			return(NULL);
		}
	}

	*Size = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size;
	if (MappedAsImage || DirectoryAddress < NtHeaders->OptionalHeader.SizeOfHeaders) {
		return((PVOID)((PCHAR)Base + DirectoryAddress));
	}

	return(RtlAddressInSectionTable((PIMAGE_NT_HEADERS)NtHeaders, Base, DirectoryAddress));
}

#define LDR_VIEW_TO_DATAFILE(x) ((PVOID)(((ULONG_PTR)(x)) |  (ULONG_PTR)1))
#define LDR_IS_DATAFILE(x)              (((ULONG_PTR)(x)) &  (ULONG_PTR)1)
#define LDR_IS_VIEW(x)                  (!LDR_IS_DATAFILE(x))
#define LDR_DATAFILE_TO_VIEW(x) ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))

PVOID
RtlImageDirectoryEntryToData(
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

	NtHeaders = RtlImageNtHeader(Base);

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

// begin_rebase
PIMAGE_BASE_RELOCATION
LdrProcessRelocationBlockLongLong(
	IN ULONG_PTR VA,
	IN ULONG SizeOfBlock,
	IN PUSHORT NextOffset,
	IN LONGLONG Diff
)
{
	PUCHAR FixupVA;
	USHORT Offset;
	LONG Temp;
	ULONGLONG Value64;

	while (SizeOfBlock--) {

		Offset = *NextOffset & (USHORT)0xfff;
		FixupVA = (PUCHAR)(VA + Offset);

		//
		// Apply the fixups.
		//

		switch ((*NextOffset) >> 12) {

		case IMAGE_REL_BASED_HIGHLOW:
			//
			// HighLow - (32-bits) relocate the high and low half
			//      of an address.
			//
			*(LONG UNALIGNED *)FixupVA += (ULONG)Diff;
			break;

		case IMAGE_REL_BASED_HIGH:
			//
			// High - (16-bits) relocate the high half of an address.
			//
			Temp = *(PUSHORT)FixupVA << 16;
			Temp += (ULONG)Diff;
			*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);
			break;

		case IMAGE_REL_BASED_HIGHADJ:
			//
			// Adjust high - (16-bits) relocate the high half of an
			//      address and adjust for sign extension of low half.
			//

			//
			// If the address has already been relocated then don't
			// process it again now or information will be lost.
			//
#define LDRP_RELOCATION_FINAL       0x2
			if (Offset & LDRP_RELOCATION_FINAL) {
				++NextOffset;
				--SizeOfBlock;
				break;
			}

			Temp = *(PUSHORT)FixupVA << 16;
			++NextOffset;
			--SizeOfBlock;
			Temp += (LONG)(*(PSHORT)NextOffset);
			Temp += (ULONG)Diff;
			Temp += 0x8000;
			*(PUSHORT)FixupVA = (USHORT)(Temp >> 16);

			break;

		case IMAGE_REL_BASED_LOW:
			//
			// Low - (16-bit) relocate the low half of an address.
			//
			Temp = *(PSHORT)FixupVA;
			Temp += (ULONG)Diff;
			*(PUSHORT)FixupVA = (USHORT)Temp;
			break;

		case IMAGE_REL_BASED_IA64_IMM64:

			//
			// Align it to bundle address before fixing up the
			// 64-bit immediate value of the movl instruction.
			//

			FixupVA = (PUCHAR)((ULONG_PTR)FixupVA & ~(15));
			Value64 = (ULONGLONG)0;

			//
			// Extract the lower 32 bits of IMM64 from bundle
			//


			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X,
				EMARCH_ENC_I17_IMM7B_SIZE_X,
				EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM7B_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X,
				EMARCH_ENC_I17_IMM9D_SIZE_X,
				EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM9D_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X,
				EMARCH_ENC_I17_IMM5C_SIZE_X,
				EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM5C_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X,
				EMARCH_ENC_I17_IC_SIZE_X,
				EMARCH_ENC_I17_IC_INST_WORD_POS_X,
				EMARCH_ENC_I17_IC_VAL_POS_X);
			EXT_IMM64(Value64,
				(PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X,
				EMARCH_ENC_I17_IMM41a_SIZE_X,
				EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41a_VAL_POS_X);

			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
				EMARCH_ENC_I17_IMM41b_SIZE_X,
				EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41b_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
				EMARCH_ENC_I17_IMM41c_SIZE_X,
				EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41c_VAL_POS_X);
			EXT_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
				EMARCH_ENC_I17_SIGN_SIZE_X,
				EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
				EMARCH_ENC_I17_SIGN_VAL_POS_X);
			//
			// Update 64-bit address
			//

			Value64 += Diff;

			//
			// Insert IMM64 into bundle
			//

			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM7B_INST_WORD_X),
				EMARCH_ENC_I17_IMM7B_SIZE_X,
				EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM7B_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM9D_INST_WORD_X),
				EMARCH_ENC_I17_IMM9D_SIZE_X,
				EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM9D_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM5C_INST_WORD_X),
				EMARCH_ENC_I17_IMM5C_SIZE_X,
				EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM5C_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IC_INST_WORD_X),
				EMARCH_ENC_I17_IC_SIZE_X,
				EMARCH_ENC_I17_IC_INST_WORD_POS_X,
				EMARCH_ENC_I17_IC_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41a_INST_WORD_X),
				EMARCH_ENC_I17_IMM41a_SIZE_X,
				EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41a_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41b_INST_WORD_X),
				EMARCH_ENC_I17_IMM41b_SIZE_X,
				EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41b_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_IMM41c_INST_WORD_X),
				EMARCH_ENC_I17_IMM41c_SIZE_X,
				EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
				EMARCH_ENC_I17_IMM41c_VAL_POS_X);
			INS_IMM64(Value64,
				((PULONG)FixupVA + EMARCH_ENC_I17_SIGN_INST_WORD_X),
				EMARCH_ENC_I17_SIGN_SIZE_X,
				EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
				EMARCH_ENC_I17_SIGN_VAL_POS_X);
			break;

		case IMAGE_REL_BASED_DIR64:

			*(ULONGLONG UNALIGNED *)FixupVA += Diff;

			break;

		case IMAGE_REL_BASED_MIPS_JMPADDR:
			//
			// JumpAddress - (32-bits) relocate a MIPS jump address.
			//
			Temp = (*(PULONG)FixupVA & 0x3ffffff) << 2;
			Temp += (ULONG)Diff;
			*(PULONG)FixupVA = (*(PULONG)FixupVA & ~0x3ffffff) |
				((Temp >> 2) & 0x3ffffff);

			break;

		case IMAGE_REL_BASED_ABSOLUTE:
			//
			// Absolute - no fixup required.
			//
			break;

		case IMAGE_REL_BASED_SECTION:
			//
			// Section Relative reloc.  Ignore for now.
			//
			break;

		case IMAGE_REL_BASED_REL32:
			//
			// Relative intrasection. Ignore for now.
			//
			break;

		default:
			//
			// Illegal - illegal relocation type.
			//

			return (PIMAGE_BASE_RELOCATION)NULL;
		}
		++NextOffset;
	}
	return (PIMAGE_BASE_RELOCATION)NextOffset;
}

NTSTATUS
LdrRelocateImageWithBias(
	__in PVOID NewBase,
	__in LONGLONG AdditionalBias
)
/*++

Routine Description:

This routine relocates an image file that was not loaded into memory
at the preferred address.

Arguments:

NewBase - Supplies a pointer to the image base.

AdditionalBias - An additional quantity to add to all fixups.  The
32-bit X86 loader uses this when loading 64-bit images
to specify a NewBase that is actually a 64-bit value.

LoaderName - Indicates which loader routine is being called from.

Success - Value to return if relocation successful.

Conflict - Value to return if can't relocate.

Invalid - Value to return if relocations are invalid.

Return Value:

Success if image is relocated.
Conflict if image can't be relocated.
Invalid if image contains invalid fixups.

--*/

{
	LONGLONG Diff;
	ULONG TotalCountBytes = 0;
	ULONG_PTR VA;
	ULONGLONG OldBase;
	ULONG SizeOfBlock;
	PUSHORT NextOffset = NULL;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION NextBlock;
	NTSTATUS Status;

	NtHeaders = RtlImageNtHeader(NewBase);
	if (NtHeaders == NULL) {
		Status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	switch (NtHeaders->OptionalHeader.Magic) {

	case IMAGE_NT_OPTIONAL_HDR32_MAGIC:

		OldBase =
			((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.ImageBase;
		break;

	case IMAGE_NT_OPTIONAL_HDR64_MAGIC:

		OldBase =
			((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.ImageBase;
		break;

	default:

		Status = STATUS_UNSUCCESSFUL;
		goto Exit;
	}

	//
	// Locate the relocation section.
	//

	NextBlock = (PIMAGE_BASE_RELOCATION)RtlImageDirectoryEntryToData(
		NewBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &TotalCountBytes);

	//
	// It is possible for a file to have no relocations, but the relocations
	// must not have been stripped.
	//

	if (!NextBlock || !TotalCountBytes) {

		if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {

			Status = STATUS_UNSUCCESSFUL;

		}
		else {
			Status = STATUS_SUCCESS;
		}

		goto Exit;
	}

	//
	// If the image has a relocation table, then apply the specified fixup
	// information to the image.
	//
	Diff = (ULONG_PTR)NewBase - OldBase + AdditionalBias;
	while (TotalCountBytes) {
		SizeOfBlock = NextBlock->SizeOfBlock;
		TotalCountBytes -= SizeOfBlock;
		SizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
		SizeOfBlock /= sizeof(USHORT);
		NextOffset = (PUSHORT)((PCHAR)NextBlock + sizeof(IMAGE_BASE_RELOCATION));

		VA = (ULONG_PTR)NewBase + NextBlock->VirtualAddress;

		if (!(NextBlock = LdrProcessRelocationBlockLongLong(VA,
			SizeOfBlock,
			NextOffset,
			Diff))) {

			Status = STATUS_UNSUCCESSFUL;
			goto Exit;
		}
	}

	Status = STATUS_SUCCESS;
Exit:
	return Status;
}



ULONG_PTR findFuncFromEat(ULONG_PTR baseOfImage, char* pszFuncName)
{
	ULONG	*lpbaseOfFunc;
	ULONG	*lpbaseOfName;
	USHORT	*lpbaseOfIndex;

	ULONG_PTR	index;
	ULONG_PTR	addressOfFunc;

	PIMAGE_DOS_HEADER		lpimageDosHeader;
	PIMAGE_NT_HEADERS		lpimageNtHeaders;
	PIMAGE_EXPORT_DIRECTORY	lpimageExportDir;

	if (MmIsAddressValid((void*)baseOfImage) == FALSE ||
		MmIsAddressValid(pszFuncName) == FALSE)
	{
		return 0;
	}

	lpimageDosHeader = (PIMAGE_DOS_HEADER)baseOfImage;
	lpimageNtHeaders = (PIMAGE_NT_HEADERS)(baseOfImage + lpimageDosHeader->e_lfanew);

	lpimageExportDir = (PIMAGE_EXPORT_DIRECTORY)(baseOfImage + lpimageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	lpbaseOfFunc = (ULONG*)(baseOfImage + lpimageExportDir->AddressOfFunctions);
	lpbaseOfName = (ULONG*)(baseOfImage + lpimageExportDir->AddressOfNames);
	lpbaseOfIndex = (USHORT*)(baseOfImage + lpimageExportDir->AddressOfNameOrdinals);

	for (index = 0; index < lpimageExportDir->NumberOfNames; index++)
	{
		addressOfFunc = baseOfImage + lpbaseOfFunc[lpbaseOfIndex[index] + lpimageExportDir->Base - 1];
		if (strcmp((char*)(baseOfImage + lpbaseOfName[index]), pszFuncName) == 0)
		{
			return addressOfFunc;
		}
	}

	return 0;
}

typedef struct _KERNEL_CHECK_INFO
{
	ULONG	Count;
	ULONG64	StartAddr;
	ULONG64 EndAddr;
}KERNEL_CHECK_INFO, *PKERNEL_CHECK_INFO;

NTSTATUS mapingFile(void* __in pdriverFileMem, void** __out lpdriverMem, PKERNEL_CHECK_INFO *lpKernelCheckInfo)
{
	ULONG	count = 0;
	ULONG	uCheckNum = 0;

	ULONG	driverMemSize;
	ULONG	Characteristics = 0;

	PKERNEL_CHECK_INFO pCheckInfo = NULL;
	//SYSTEM_MODULE			systemModule;

	PIMAGE_DOS_HEADER		lpimageDosHeader;
	PIMAGE_NT_HEADERS		lpimageNtHeaders;
	PIMAGE_SECTION_HEADER	pimageSectionHeaders;

	if (MmIsAddressValid(pdriverFileMem) == FALSE ||
		MmIsAddressValid(lpdriverMem) == FALSE)
	{
		return STATUS_UNSUCCESSFUL;
	}


	pCheckInfo = ExAllocatePool(NonPagedPool, sizeof(KERNEL_CHECK_INFO) * 50);// 最多50个节要检查

	if (pCheckInfo == NULL)
		return STATUS_UNSUCCESSFUL;

	RtlZeroMemory(pCheckInfo, sizeof(KERNEL_CHECK_INFO) * 50);

	lpimageDosHeader = (PIMAGE_DOS_HEADER)pdriverFileMem;
	lpimageNtHeaders = (PIMAGE_NT_HEADERS)((UCHAR*)pdriverFileMem + lpimageDosHeader->e_lfanew);
	driverMemSize = lpimageNtHeaders->OptionalHeader.SizeOfImage;

	//我们申请内存
	*lpdriverMem = ExAllocatePool(NonPagedPool, driverMemSize);
	if (*lpdriverMem == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}

	RtlZeroMemory(*lpdriverMem, driverMemSize);
	//把dos nt 头装进去
	memcpy(*lpdriverMem, pdriverFileMem, lpimageNtHeaders->OptionalHeader.SizeOfHeaders);

	pimageSectionHeaders = (PIMAGE_SECTION_HEADER)((UCHAR*)lpimageNtHeaders + sizeof(IMAGE_NT_HEADERS));
	for (count; count < lpimageNtHeaders->FileHeader.NumberOfSections; count++)
	{
		Characteristics = pimageSectionHeaders[count].Characteristics;
		// 0x60000020
		if ((Characteristics & 0x60000020) == 0x60000020) //可读 代码 可执行	
		{
			pCheckInfo[uCheckNum].StartAddr = (ULONG64)((UCHAR*)(*lpdriverMem) + pimageSectionHeaders[count].VirtualAddress);
			pCheckInfo[uCheckNum].EndAddr = pCheckInfo[uCheckNum].StartAddr + RetMin(pimageSectionHeaders[count].SizeOfRawData, pimageSectionHeaders[count].Misc.VirtualSize);
			//DbgPrint("%s\n", pimageSectionHeaders[count].Name);
			uCheckNum++;
		}

		memcpy((void*)((UCHAR*)(*lpdriverMem) + pimageSectionHeaders[count].VirtualAddress), \
			(void*)((UCHAR*)pdriverFileMem + pimageSectionHeaders[count].PointerToRawData), \
			RetMin(pimageSectionHeaders[count].SizeOfRawData, pimageSectionHeaders[count].Misc.VirtualSize));
	}

	//重定位基址
	if (!NT_SUCCESS(LdrRelocateImageWithBias(*lpdriverMem, 0)))
	{
		ExFreePool(pCheckInfo);
		ExFreePool(*lpdriverMem);
		return STATUS_UNSUCCESSFUL;
	}

	pCheckInfo[0].Count = uCheckNum;
	*lpKernelCheckInfo = pCheckInfo;
	return STATUS_SUCCESS;
}

NTSTATUS loadFileToMem(WCHAR *pwszFileName, __out void** lpDriverMem, PKERNEL_CHECK_INFO *lpKernelCheckInfo)
{
	HANDLE		handleOfFile;
	HANDLE		handleOfEvent;
	NTSTATUS	st;
	void*		lpFileMem;

	LARGE_INTEGER fileOperationSize;
	UNICODE_STRING usFileName;
	OBJECT_ATTRIBUTES objectAttr;
	IO_STATUS_BLOCK ioStatusBolck;
	FILE_STANDARD_INFORMATION fileStandardInfo;

	st = STATUS_UNSUCCESSFUL;
	if (MmIsAddressValid(pwszFileName) == FALSE)
	{
		return st;
	}

	RtlInitUnicodeString(&usFileName, pwszFileName);
	InitializeObjectAttributes(&objectAttr, &usFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	memset(&ioStatusBolck, 0, sizeof(IO_STATUS_BLOCK));
	memset(&fileOperationSize, 0, sizeof(LARGE_INTEGER));

	st = ZwCreateFile(&handleOfFile, FILE_READ_DATA, &objectAttr, &ioStatusBolck, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(st))
	{
		return st;
	}

	st = ZwQueryInformationFile(handleOfFile, &ioStatusBolck, &fileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(st))
	{
		ZwClose(handleOfFile);
		return st;
	}

	lpFileMem = ExAllocatePool(NonPagedPool, fileStandardInfo.EndOfFile.QuadPart);
	if (lpFileMem == NULL)
	{
		ZwClose(handleOfFile);
		return st;
	}

	InitializeObjectAttributes(&objectAttr, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	st = ZwCreateEvent(&handleOfEvent, EVENT_ALL_ACCESS, &objectAttr, NotificationEvent, FALSE);
	if (!NT_SUCCESS(st))
	{
		ZwClose(handleOfFile);
		return st;
	}
	st = ZwReadFile(handleOfFile, handleOfEvent, NULL, NULL, &ioStatusBolck, lpFileMem, fileStandardInfo.EndOfFile.QuadPart, &fileOperationSize, NULL);
	if (!NT_SUCCESS(st))
	{
		ExFreePool(lpFileMem);
		ZwClose(handleOfFile);
		ZwClose(handleOfEvent);
		return st;
	}

	if (st == STATUS_PENDING)
	{
		ZwWaitForSingleObject(handleOfEvent, FALSE, NULL);
	}

	ZwClose(handleOfEvent);

	st = mapingFile(lpFileMem, lpDriverMem, lpKernelCheckInfo);
	if (!NT_SUCCESS(st))
	{
		ExFreePool(lpFileMem);
		ZwClose(handleOfFile);
		return st;
	}

	ExFreePool(lpFileMem);
	ZwClose(handleOfFile);
	return st;
}

//////////////////////////////////////////////////////////////////////////


