// @afx_IDE

#include <stdio.h>
#include <Windows.h>
#include <winternl.h>

BOOL ReadPE(LPCSTR lpPEfileName, PBYTE* pPEbaseAddress, SIZE_T* sPEsize) {

	HANDLE hPEfileHandle = INVALID_HANDLE_VALUE;
	PBYTE pBuffer = NULL;
	DWORD dwPEfileSize = NULL;
	DWORD dwNumberOfBytesRead = NULL;

	printf("\nReading: \"%s\" \n", lpPEfileName);

	hPEfileHandle = CreateFileA(lpPEfileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPEfileHandle == INVALID_HANDLE_VALUE) {
		printf("CreateFile failed\n Error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	dwPEfileSize = GetFileSize(hPEfileHandle, NULL);
	if (dwPEfileSize == NULL) {
		printf("GetFileSize failed\n Error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwPEfileSize);
	if (pBuffer == NULL) {
		printf("HeapAlloc failed\n Error: %d", GetLastError());
		goto _EndOfFunction;
	}

	if (!ReadFile(hPEfileHandle, pBuffer, dwPEfileSize, &dwNumberOfBytesRead, NULL) || dwPEfileSize != dwNumberOfBytesRead) {
		printf("ReadFile failed\n Error: %d", GetLastError());
		goto _EndOfFunction;
	}

	printf("\nFile reading complete \n\n");

_EndOfFunction:
	*pPEbaseAddress = (PBYTE)pBuffer;
	*sPEsize = (SIZE_T)dwPEfileSize;
	if (hPEfileHandle)
		CloseHandle(hPEfileHandle);
	if (*pPEbaseAddress == NULL || *sPEsize == NULL)
		return FALSE;
	return TRUE;
}


VOID PEparsing(PBYTE pPEbaseAddress) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPEbaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return;
	}

	PIMAGE_NT_HEADERS pNTheaders = (PIMAGE_NT_HEADERS)(pPEbaseAddress + pDosHeader->e_lfanew);
	if (pNTheaders->Signature != IMAGE_NT_SIGNATURE) {
		return;
	}

	printf("\n\n\n\n \t |--------------- File Header ---------------| \n \n");

	IMAGE_FILE_HEADER FileHeader = pNTheaders->FileHeader;

	if (FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
		printf("\t  File detected as: ");

		if (FileHeader.Characteristics & IMAGE_FILE_DLL)
			printf("Dynamic Link Library (DLL)");
		else if (FileHeader.Characteristics & IMAGE_SUBSYSTEM_NATIVE)
			printf("SYS file");
		else
			printf("Executable (EXE)");
	}

	printf("\n\t  File Architecture (via File Header): %s \n", FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? "x32" : "x64");
	printf("\t  Number of Sections: %d \n", FileHeader.NumberOfSections);
	printf("\t  Size of optional header: %d \n", FileHeader.SizeOfOptionalHeader);

	printf("\n\n\n\n \t |--------------- Optional Header ---------------| \n \n");

	IMAGE_OPTIONAL_HEADER OptionalHeader = pNTheaders->OptionalHeader;
	if (OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		return;
	}

	printf("\t  File Architecure (via Optional Header): %s \n", OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "x32" : "x64");
	printf("\t  Size of code section: %d \n", OptionalHeader.SizeOfCode);
	printf("\t  Address of code section: 0x%p \t[Relative Virtual Address: 0x%0.8X]\n", (PVOID)(pPEbaseAddress + OptionalHeader.BaseOfCode), OptionalHeader.BaseOfCode);
	printf("\t  Size of initialized data: %d \n", OptionalHeader.SizeOfInitializedData);
	printf("\t  Size of uninitialized data: %d \n", OptionalHeader.SizeOfUninitializedData);
	printf("\t  Preferred base address: 0x%p \n", (PVOID)OptionalHeader.ImageBase);
	printf("\t  Required OS version: %d.%d \n", OptionalHeader.MajorOperatingSystemVersion, OptionalHeader.MinorOperatingSystemVersion);
	printf("\t  Address of entry point: 0x%p \t[Relative Virtual Address: 0x%0.8X]\n", (PVOID)(pPEbaseAddress + OptionalHeader.AddressOfEntryPoint), OptionalHeader.AddressOfEntryPoint);
	printf("\t  Size of image: %d \n", OptionalHeader.SizeOfImage);
	printf("\t  Checksum: 0x%0.8X \n", OptionalHeader.CheckSum);
	printf("\t  No. of entries in DataDirectory array: %d \n", OptionalHeader.NumberOfRvaAndSizes);

	printf("\n\n\n\n \t |--------------- Directories ---------------| \n \n");

	printf("\t  Export directory located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	printf("\t  Import directory located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	printf("\t  Resource directory located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);

	printf("\t  Exception directory located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);

	printf("\t  Base Relocation table located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	printf("\t  TLS directory located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

	printf("\t  Import Address Table located at: 0x%p  Size: %d \t[Relative Virtual Address: 0x%0.8X]\n",
		(PVOID)(pPEbaseAddress + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress),
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size,
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);

	printf("\n\n\n\n \t |--------------- Sections ---------------| \n \n");

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)pNTheaders) + sizeof(IMAGE_NT_HEADERS));
	for (size_t i = 0; i < pNTheaders->FileHeader.NumberOfSections; i++) {
		printf("\t  ................................\n");
		printf("\t  Section Name: %s \n", (CHAR*)pSectionHeader->Name);
		printf("\t  Size: %d \n", pSectionHeader->SizeOfRawData);
		printf("\t  Relative Virtual Address: 0x%0.8X \n", pSectionHeader->VirtualAddress);
		printf("\t  Address: 0x%p \n", (PVOID)(pPEbaseAddress + pSectionHeader->VirtualAddress));
		printf("\t  Number of Relocations: %d \n", pSectionHeader->NumberOfRelocations);
		printf("\t  Permissions: ");
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			printf(" PAGE_READONLY ");
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE && pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			printf(" PAGE_READWRITE ");
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			printf(" PAGE_EXECUTE ");
		if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE && pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ)
			printf(" PAGE_EXECUTE_READWRITE ");
			printf("\n\t  ................................\n\n\n");;

		pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pSectionHeader + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}
}


int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: PEparser.exe [PE File to parse] \n");
		return -1;
	}

	PBYTE pPEbaseAddress = NULL;
	SIZE_T sPEsize = NULL;

	if (!ReadPE(argv[1], &pPEbaseAddress, &sPEsize)) {
		return -1;
	}

	printf("\"%s\" Read from: 0x%p \t\t Size: %d bytes \n", argv[1], pPEbaseAddress, sPEsize);

	PEparsing(pPEbaseAddress);

	printf("\n\nPress ENTER to quit \n");
	getchar();

	HeapFree(GetProcessHeap(), NULL, pPEbaseAddress);

	return 0;
}
