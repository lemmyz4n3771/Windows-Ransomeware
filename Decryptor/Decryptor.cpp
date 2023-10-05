#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <bcrypt.h>
#include <iomanip>
#include <Shlwapi.h>
#include <ctype.h>
#include <string>

#pragma comment( lib, "Shlwapi" )
#pragma comment( lib, "Bcrypt" )
#pragma comment( lib, "Crypt32" )
namespace fs = std::filesystem;

std::vector<char> ReadBytes(char const* filename) {
	std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
	std::ifstream::pos_type pos = ifs.tellg();

	if (pos == 0)
		return std::vector<char>{};

	std::vector<char> fileContents(pos);
	ifs.seekg(0, std::ios::beg);
	ifs.read(&fileContents[0], pos);

	return fileContents;
}

BOOL WriteDecryptedToFile(const char* filename, PBYTE pbData, DWORD dwDataLen) {
	BOOL result = TRUE;
	HANDLE hFile = nullptr;

	PathRemoveExtension((LPSTR)filename);

	hFile = CreateFileA(filename,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	BOOL bResult = TRUE;

	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		bResult = FALSE;
		std::cout << "[-] CreateFileA failed: " << std::hex << GetLastError();
		goto Cleanup;
	}
	{
		DWORD dwWritten = 0;
		WriteFile(hFile, pbData, dwDataLen, &dwWritten, nullptr);
		std::cout << "[+] Wrote " << dwWritten << " bytes" << std::endl;
		goto Cleanup;
	}
Cleanup:
	if (hFile)
		CloseHandle(hFile);

	return result;

}

BOOL AESDecrypt(std::vector<char> encryptedData, DWORD dwEncryptedDataLen, unsigned char* key,
	DWORD dwKeyLen, unsigned char* iv, DWORD dwIVLen, PBYTE* lpDecryptedOut, PDWORD dwDecryptedOutLen) {

	NTSTATUS success = NO_ERROR;
	BOOL bResult = FALSE;
	
	if (encryptedData.empty() || dwEncryptedDataLen <= 0 || !lpDecryptedOut || !dwDecryptedOutLen) {
		std::cerr << "[-] Parameters are invalid" << std::endl;
		return FALSE;
	}
	char* pbEncryptedData = &encryptedData[0];
	std::cout << "Inside AESDecrypt..." << std::endl;
	BCRYPT_ALG_HANDLE hCryptProv = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	success = BCryptOpenAlgorithmProvider(&hCryptProv, BCRYPT_AES_ALGORITHM, NULL, 0);
	std::cout << "Finished BCryptOpenAlgorithmProvider..." << std::endl;
	bResult = (success == NO_ERROR);
	if (!bResult) {
		std::cerr << "[-] BCryptOpenAlgorithmProvider error: " << std::hex << success << std::endl;
		goto Cleanup;
	}

	success = BCryptGenerateSymmetricKey(hCryptProv, &hKey, NULL, 0, key, dwKeyLen, 0);
	std::cout << "Finished BCryptGenerateSymmetricKey..." << std::endl;
	bResult = (success == NO_ERROR);
	if (!bResult) {
		std::cerr << "[-] BCryptGenerateSymmetricKey error: " << std::hex << success << std::endl;
		goto Cleanup;
	}

	success = BCryptDecrypt(hKey, (unsigned char*)pbEncryptedData, dwEncryptedDataLen, NULL, iv,
		dwIVLen, NULL, 0, dwDecryptedOutLen, BCRYPT_BLOCK_PADDING);
	std::cout << "Finished BCryptDecrypt..." << std::endl;
	bResult = (success == NO_ERROR);
	if (!bResult) {
		std::cout << "[-] BCryptDecrypt error: " << std::hex << success << std::endl;
		goto Cleanup;
	}

	*lpDecryptedOut = (PBYTE)VirtualAlloc(nullptr, *dwDecryptedOutLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	std::cout << "Finished VirtualAlloc..." << std::endl;
	bResult = (*lpDecryptedOut != nullptr);
	if (!bResult) {
		std::cout << "[-] VirtualAlloc error: " << std::hex << GetLastError() << std::endl;
		goto Cleanup;
	}

	success = BCryptDecrypt(hKey, (unsigned char*)pbEncryptedData, dwEncryptedDataLen, NULL, iv, dwIVLen,
		*lpDecryptedOut, *dwDecryptedOutLen, dwDecryptedOutLen, BCRYPT_BLOCK_PADDING);
	std::cout << "Finished BCryptDecrypt..." << std::endl;
	bResult = (success == NO_ERROR);
	if (!bResult) {
		HeapFree(GetProcessHeap(), 0, *lpDecryptedOut);
		*lpDecryptedOut = nullptr;
		std::cerr << "[-] BCryptDecrypt error: " << std::hex << success << std::endl;
		goto Cleanup;
	}


Cleanup:
	if (hKey)
		BCryptDestroyKey(hKey);
	if (hCryptProv)
		BCryptCloseAlgorithmProvider(hCryptProv, 0);
	return bResult;

}

int main(int argc, char** argv) {

	if ((argc < 2)) {
		exit(0);
	}
	char* dir = argv[1];
	unsigned char key[32] = { 0xd7, 0xe1, 0xa5, 0xa5, 0xb1, 0xbc, 0xf5, 0x48, 0xd9, 0x18, 0x7f, 0x18, 0x89, 0x36, 0xcd, 0x42, 0x79, 0xc3, 0x81, 0x54, 0xfa, 0xff, 0x1e, 0x60, 0x1c, 0xfd, 0xe5, 0x4c, 0x7b, 0x0c, 0x5f, 0x4a };
	DWORD dwKeyLen = sizeof(key);

	unsigned char iv[32] = { 0xce, 0x84, 0x7e, 0xfa, 0x56, 0xf0, 0x80, 0xbb, 0x53, 0x8f, 0xc9, 0x39, 0xa6, 0x40, 0xa7, 0x3d, 0x5b, 0xcf, 0x20, 0x6b, 0x03, 0x70, 0x18, 0x87, 0xff, 0x93, 0x37, 0xa1, 0x55, 0xb7, 0xf4, 0x87 };
	DWORD dwIVLen = sizeof(iv);

	for (const fs::directory_entry& entry : fs::recursive_directory_iterator(dir)) {

		if (lstrcmp(PathFindExtensionA(entry.path().string().c_str()), ".enc") == 0) {
			std::cout << "[*] Decrypting " << entry << " ......." << std::endl;
			PBYTE pbFileContents = nullptr;
			DWORD dwFileContentLength = 0;
			BOOL bResult = FALSE;

			std::vector<char> contents = ReadBytes(entry.path().string().c_str());

			HANDLE hFile = nullptr;

			PBYTE pbDecryptedData = nullptr;
			DWORD dwDecryptedDataLen = 0;

			bResult = AESDecrypt(contents, contents.size(), key, dwKeyLen, iv, dwIVLen, &pbDecryptedData, &dwDecryptedDataLen);
			if (!bResult) {
				std::cerr << "[-] AESDecrypt Error" << std::endl;
				continue;
			}
			std::cout << "[+] Decryption completed" << std::endl;
			bResult = WriteDecryptedToFile(entry.path().string().c_str(), pbDecryptedData, dwDecryptedDataLen);
			if (!bResult) {
				std::cerr << "[-] WriteDecryptedToFile Error" << std::endl;
				continue;
			}
			std::cout << "[+] Decrypted file write completed!" << std::endl;
		}
	}
	return 0;
}