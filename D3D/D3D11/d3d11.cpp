// proxydll.cpp
#include "stdafx.h"
#include "proxydll.h"
#define NO_STEREO_D3D9
#define NO_STEREO_D3D10
#include "..\nvstereo.h"
#include <Xinput.h>
#include <D3Dcompiler.h>
#include <DirectXMath.h>
#define _USE_MATH_DEFINES
#include <math.h>
#include "resource.h"
#include "..\Nektra\NktHookLib.h"
#include "..\vkeys.h"
#include "..\log.h"

// global variables
#pragma data_seg (".d3d11_shared")
HINSTANCE			gl_hThisInstance;
HINSTANCE           gl_hOriginalDll = NULL;
bool				gl_hookedDevice = false;
bool				gl_hookedContext = false;
bool				gl_dumpBin = false;
bool				gl_log = false;
bool				gl_hunt = false;
bool				gl_cache_shaders = false;
bool				gl_fix_enabled = true;
CRITICAL_SECTION	gl_CS;
// Our parameters for the stereo parameters texture.
DirectX::XMFLOAT4	iniParams = { FLT_MAX, FLT_MAX, FLT_MAX, FLT_MAX };
FILE*				LogFile = NULL;
#pragma data_seg ()

CNktHookLib cHookMgr;

typedef HMODULE(WINAPI *lpfnLoadLibraryExW)(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags);
static HMODULE WINAPI Hooked_LoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags);
static struct
{
	SIZE_T nHookId;
	lpfnLoadLibraryExW fnLoadLibraryExW;
} sLoadLibraryExW_Hook = { 40, NULL };

// Function called for every LoadLibraryExW call once we have hooked it.  
// We want to look for overrides to System32 that we can circumvent.  This only happens
// in the current process, not system wide.
//
// Looking for: nvapi64.dll	LoadLibraryExW("C:\Windows\system32\d3d11.dll", NULL, 0)
//
// Cleanly fetch system directory, as drive may not be C:, and it doesn't have to be 
// "C:\Windows\system32", although that will be the path for both 32 bit and 64 bit OS.

static HMODULE WINAPI Hooked_LoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags)
{
	WCHAR systemPath[MAX_PATH];
	GetSystemDirectoryW(systemPath, sizeof(systemPath));
	wcscat_s(systemPath, MAX_PATH, L"\\d3d11.dll");

	// Bypass the known expected call from our wrapped d3d11, where it needs to call to the system to get APIs.
	// This is a bit of a hack, but if the string comes in as original_d3d11, that's from us, and needs to switch 
	// to the real one. This doesn't need to be case insensitive, because we create the original string, all lower case.
	if (wcsstr(lpLibFileName, L"d3d11_org.dll") != NULL) {
		return sLoadLibraryExW_Hook.fnLoadLibraryExW(systemPath, hFile, dwFlags);
	}

	// This is to be case insenstive as we don't know if NVidia will change that and otherwise break it
	// it with a driver upgrade.  Any direct access to system32\d3d11.dll needs to be reset to us.
	if (_wcsicmp(lpLibFileName, systemPath) == 0) {
		return sLoadLibraryExW_Hook.fnLoadLibraryExW(L"d3d11.dll", hFile, dwFlags);
	}

	// Normal unchanged case.
	return sLoadLibraryExW_Hook.fnLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

static bool InstallHooks()
{
	HINSTANCE hKernel32;
	LPVOID fnOrigLoadLibrary;
	DWORD dwOsErr;

	hKernel32 = NktHookLibHelpers::GetModuleBaseAddress(L"Kernel32.dll");

	// Only ExW version for now, used by nvapi.
	fnOrigLoadLibrary = NktHookLibHelpers::GetProcedureAddress(hKernel32, "LoadLibraryExW");

	dwOsErr = cHookMgr.Hook(&(sLoadLibraryExW_Hook.nHookId), (LPVOID*)&(sLoadLibraryExW_Hook.fnLoadLibraryExW), fnOrigLoadLibrary, Hooked_LoadLibraryExW);

	return (dwOsErr == 0) ? true : false;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	bool result = true;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		gl_hThisInstance = hinstDLL;
		InitInstance();
		result = InstallHooks();
		ShowStartupScreen();
		break;

	case DLL_PROCESS_DETACH:
		ExitInstance();
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;
	}

	return result;
}

// 64 bit magic FNV-0 and FNV-1 prime
#define FNV_64_PRIME ((UINT64)0x100000001b3ULL)
static UINT64 fnv_64_buf(const void *buf, size_t len)
{
	UINT64 hval = 0;
	unsigned const char *bp = (unsigned const char *)buf;	/* start of buffer */
	unsigned const char *be = bp + len;		/* beyond end of buffer */

	// FNV-1 hash each octet of the buffer
	while (bp < be) {
		// multiply by the 64 bit FNV magic prime mod 2^64 */
		hval *= FNV_64_PRIME;
		// xor the bottom with the current octet
		hval ^= (UINT64)*bp++;
	}
	return hval;
}

map<UINT64, bool> isCache;
map<UINT64, bool> hasStartPatch;
map<UINT64, bool> hasStartFix;

map <UINT64, vector<byte>*> origShaderData;
map<ID3D11VertexShader *, UINT64> shaderMapVS;
map<ID3D11PixelShader *, UINT64> shaderMapPS;
map<ID3D11ComputeShader *, UINT64> shaderMapCS;
map<ID3D11GeometryShader *, UINT64> shaderMapGS;
map<ID3D11DomainShader *, UINT64> shaderMapDS;
map<ID3D11HullShader *, UINT64> shaderMapHS;

map<ID3D11PixelShader *, ID3D11PixelShader *> PSmap;
map<ID3D11VertexShader *, ID3D11VertexShader *> VSmap;
map<ID3D11ComputeShader *, ID3D11ComputeShader *> CSmap;
map<ID3D11GeometryShader *, ID3D11GeometryShader *> GSmap;
map<ID3D11DomainShader *, ID3D11DomainShader *> DSmap;
map<ID3D11HullShader *, ID3D11HullShader *> HSmap;

map<UINT64, UINT64> crc2;

ID3D11VertexShader * currentVS;
ID3D11PixelShader * currentPS;
ID3D11ComputeShader * currentCS;
ID3D11GeometryShader * currentGS;
ID3D11DomainShader * currentDS;
ID3D11HullShader * currentHS;

char cwd[MAX_PATH];

typedef HRESULT(STDMETHODCALLTYPE* D3D11_VS)(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11VertexShader **ppVertexShader);
static struct {
	SIZE_T nHookId;
	D3D11_VS fnCreateVertexShader;
} sCreateVertexShader_Hook = { 1, NULL };
HRESULT STDMETHODCALLTYPE D3D11_CreateVertexShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11VertexShader **ppVertexShader) {
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	char buffer[80];
	char path[MAX_PATH];
	
	LogInfo("Create VertexShader: %016llX\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dumpBin) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-vs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	ID3D11VertexShader *pVertexShaderNew;
	HRESULT res = sCreateVertexShader_Hook.fnCreateVertexShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppVertexShader);
	if (isCache.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);
		_crc2 = fnv_64_buf(file.data(), file.size());
		res = sCreateVertexShader_Hook.fnCreateVertexShader(This, file.data(), file.size(), pClassLinkage, &pVertexShaderNew);
	} else if (hasStartPatch.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		vector<byte> byteCode(BytecodeLength);
		memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

		byteCode = assembler(file, byteCode);
		_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
		if (gl_cache_shaders) {
			FILE* f;
			sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.bin", _crc);
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, buffer);
			
			EnterCriticalSection(&gl_CS);
			fopen_s(&f, path, "wb");
			fwrite(byteCode.data(), 1, byteCode.size(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
		res = sCreateVertexShader_Hook.fnCreateVertexShader(This, byteCode.data(), byteCode.size(), pClassLinkage, &pVertexShaderNew);
	} else if (hasStartFix.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		string shdModel = "vs_5_0";
		ID3DBlob* pByteCode = nullptr;
		ID3DBlob* pErrorMsgs = nullptr;
		HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
			"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
		if (ret == S_OK) {
			_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
			if (gl_cache_shaders) {
				FILE* f;
				sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);

				EnterCriticalSection(&gl_CS);
				fopen_s(&f, path, "wb");
				fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			res = sCreateVertexShader_Hook.fnCreateVertexShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &pVertexShaderNew);
		} else {
			LogInfo("compile error:%s\n", path);
		}
	}
	if (ppVertexShader != NULL && *ppVertexShader != NULL) {
		shaderMapVS[*ppVertexShader] = _crc;
		VSmap[*ppVertexShader] = *ppVertexShader;
		if (_crc2) {
			crc2[_crc] = _crc2;
			VSmap[*ppVertexShader] = pVertexShaderNew;
		}
	}
	return res;
}
typedef HRESULT(STDMETHODCALLTYPE* D3D11_PS)(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11PixelShader **ppPixelShader);
static struct {
	SIZE_T nHookId;
	D3D11_PS fnCreatePixelShader;
} sCreatePixelShader_Hook = { 2, NULL };
HRESULT STDMETHODCALLTYPE D3D11_CreatePixelShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11PixelShader **ppPixelShader) {
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	char buffer[80];
	char path[MAX_PATH];

	LogInfo("Create PixelShader: %016llX\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dumpBin) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-ps.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	ID3D11PixelShader* pPixelShaderNew;
	HRESULT res = sCreatePixelShader_Hook.fnCreatePixelShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader);
	if (isCache.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);
		_crc2 = fnv_64_buf(file.data(), file.size());
		res = sCreatePixelShader_Hook.fnCreatePixelShader(This, file.data(), file.size(), pClassLinkage, &pPixelShaderNew);
	} else if (hasStartPatch.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		vector<byte> byteCode(BytecodeLength);
		memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

		byteCode = assembler(file, byteCode);
		_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
		if (gl_cache_shaders) {
			FILE* f;
			sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.bin", _crc);
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, buffer);

			EnterCriticalSection(&gl_CS);
			fopen_s(&f, path, "wb");
			fwrite(byteCode.data(), 1, byteCode.size(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
		res = sCreatePixelShader_Hook.fnCreatePixelShader(This, byteCode.data(), byteCode.size(), pClassLinkage, &pPixelShaderNew);
	} else if (hasStartFix.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		string shdModel = "ps_5_0";
		ID3DBlob* pByteCode = nullptr;
		ID3DBlob* pErrorMsgs = nullptr;
		HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
			"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
		if (ret == S_OK) {
			_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
			if (gl_cache_shaders) {
				FILE* f;
				sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);

				EnterCriticalSection(&gl_CS);
				fopen_s(&f, path, "wb");
				fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			res = sCreatePixelShader_Hook.fnCreatePixelShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &pPixelShaderNew);
		} else {
			LogInfo("compile error:\n%s", path);
		}
	}
	if (ppPixelShader != NULL && *ppPixelShader != NULL) {
		shaderMapPS[*ppPixelShader] = _crc;
		PSmap[*ppPixelShader] = *ppPixelShader;
		if (_crc2) {
			crc2[_crc] = _crc2;
			PSmap[*ppPixelShader] = pPixelShaderNew;
		}
	}
	return res;
}
typedef HRESULT(STDMETHODCALLTYPE* D3D11_CS)(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11ComputeShader **ppComputeShader);
static struct {
	SIZE_T nHookId;
	D3D11_CS fnCreateComputeShader;
} sCreateComputeShader_Hook = { 3, NULL };
HRESULT STDMETHODCALLTYPE D3D11_CreateComputeShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11ComputeShader **ppComputeShader) {
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	char buffer[80];
	char path[MAX_PATH];

	LogInfo("Create ComputeShader: %016llX\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dumpBin) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-cs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	ID3D11ComputeShader* pComputeShaderNew;
	HRESULT res = sCreateComputeShader_Hook.fnCreateComputeShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppComputeShader);
	if (isCache.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-cs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);
		_crc2 = fnv_64_buf(file.data(), file.size());
		res = sCreateComputeShader_Hook.fnCreateComputeShader(This, file.data(), file.size(), pClassLinkage, &pComputeShaderNew);
	} else if (hasStartPatch.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-cs.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		vector<byte> byteCode(BytecodeLength);
		memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

		byteCode = assembler(file, byteCode);
		_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
		if (gl_cache_shaders) {
			FILE* f;
			sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-cs.bin", _crc);
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, buffer);

			EnterCriticalSection(&gl_CS);
			fopen_s(&f, path, "wb");
			fwrite(byteCode.data(), 1, byteCode.size(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
		res = sCreateComputeShader_Hook.fnCreateComputeShader(This, byteCode.data(), byteCode.size(), pClassLinkage, &pComputeShaderNew);
	} else if (hasStartFix.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-cs_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		string shdModel = "cs_5_0";
		ID3DBlob* pByteCode = nullptr;
		ID3DBlob* pErrorMsgs = nullptr;
		HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
			"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
		if (ret == S_OK) {
			_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
			if (gl_cache_shaders) {
				FILE* f;
				sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-cs.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);

				EnterCriticalSection(&gl_CS);
				fopen_s(&f, path, "wb");
				fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			res = sCreateComputeShader_Hook.fnCreateComputeShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &pComputeShaderNew);
		} else {
			LogInfo("compile error:\n%s", path);
		}
	}
	if (*ppComputeShader != NULL) {
		shaderMapCS[*ppComputeShader] = _crc;
		CSmap[*ppComputeShader] = *ppComputeShader;
		if (_crc2) {
			crc2[_crc] = _crc2;
			CSmap[*ppComputeShader] = pComputeShaderNew;
		}
	}
	return res;
}
typedef HRESULT(STDMETHODCALLTYPE* D3D11_GS)(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11GeometryShader **ppGeometryShader);
static struct {
	SIZE_T nHookId;
	D3D11_GS fnCreateGeometryShader;
} sCreateGeometryShader_Hook = { 4, NULL };
HRESULT STDMETHODCALLTYPE D3D11_CreateGeometryShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11GeometryShader **ppGeometryShader) {
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	char buffer[80];
	char path[MAX_PATH];

	LogInfo("Create GeometryShader: %016llX\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dumpBin) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-gs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	ID3D11GeometryShader *pGeometryShaderNew;
	HRESULT res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppGeometryShader);
	if (isCache.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-gs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);
		_crc2 = fnv_64_buf(file.data(), file.size());
		res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, file.data(), file.size(), pClassLinkage, &pGeometryShaderNew);
	} else if (hasStartPatch.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-gs.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		vector<byte> byteCode(BytecodeLength);
		memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

		byteCode = assembler(file, byteCode);
		_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
		if (gl_cache_shaders) {
			FILE* f;
			sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-gs.bin", _crc);
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, buffer);

			EnterCriticalSection(&gl_CS);
			fopen_s(&f, path, "wb");
			fwrite(byteCode.data(), 1, byteCode.size(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
		res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, byteCode.data(), byteCode.size(), pClassLinkage, &pGeometryShaderNew);
	} else if (hasStartFix.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-gs_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		string shdModel = "gs_5_0";
		ID3DBlob* pByteCode = nullptr;
		ID3DBlob* pErrorMsgs = nullptr;
		HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
			"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
		if (ret == S_OK) {
			_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
			if (gl_cache_shaders) {
				FILE* f;
				sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-gs.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);

				EnterCriticalSection(&gl_CS);
				fopen_s(&f, path, "wb");
				fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &pGeometryShaderNew);
		} else {
			LogInfo("compile error:\n%s", path);
		}
	}
	if (*ppGeometryShader != NULL) {
		shaderMapGS[*ppGeometryShader] = _crc;
		GSmap[*ppGeometryShader] = *ppGeometryShader;
		if (_crc2) {
			crc2[_crc] = _crc2;
			GSmap[*ppGeometryShader] = pGeometryShaderNew;
		}
	}
	return res;
}
typedef HRESULT(STDMETHODCALLTYPE* D3D11_DS)(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11DomainShader **ppDomainShader);
static struct {
	SIZE_T nHookId;
	D3D11_DS fnCreateDomainShader;
} sCreateDomainShader_Hook = { 5, NULL };
HRESULT STDMETHODCALLTYPE D3D11_CreateDomainShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11DomainShader **ppDomainShader) {
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	char buffer[80];
	char path[MAX_PATH];

	LogInfo("Create ComputeShader: %016llX\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dumpBin) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-ds.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	ID3D11DomainShader* pDomainShaderNew;
	HRESULT res = sCreateDomainShader_Hook.fnCreateDomainShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppDomainShader);
	if (isCache.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ds.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);
		_crc2 = fnv_64_buf(file.data(), file.size());
		res = sCreateDomainShader_Hook.fnCreateDomainShader(This, file.data(), file.size(), pClassLinkage, &pDomainShaderNew);
	} else if (hasStartPatch.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ds.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		vector<byte> byteCode(BytecodeLength);
		memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

		byteCode = assembler(file, byteCode);
		_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
		if (gl_cache_shaders) {
			FILE* f;
			sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ds.bin", _crc);
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, buffer);

			EnterCriticalSection(&gl_CS);
			fopen_s(&f, path, "wb");
			fwrite(byteCode.data(), 1, byteCode.size(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
		res = sCreateDomainShader_Hook.fnCreateDomainShader(This, byteCode.data(), byteCode.size(), pClassLinkage, &pDomainShaderNew);
	} else if (hasStartFix.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ds_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		string shdModel = "ds_5_0";
		ID3DBlob* pByteCode = nullptr;
		ID3DBlob* pErrorMsgs = nullptr;
		HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
			"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
		if (ret == S_OK) {
			_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
			if (gl_cache_shaders) {
				FILE* f;
				sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ds.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);

				EnterCriticalSection(&gl_CS);
				fopen_s(&f, path, "wb");
				fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			res = sCreateDomainShader_Hook.fnCreateDomainShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &pDomainShaderNew);
		} else {
			LogInfo("compile error:\n%s", path);
		}
	}
	if (*ppDomainShader != NULL) {
		shaderMapDS[*ppDomainShader] = _crc;
		DSmap[*ppDomainShader] = *ppDomainShader;
		if (_crc2) {
			crc2[_crc] = _crc2;
			DSmap[*ppDomainShader] = pDomainShaderNew;
		}
	}
	return res;
}
typedef HRESULT(STDMETHODCALLTYPE* D3D11_HS)(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11HullShader **ppHullShader);
static struct {
	SIZE_T nHookId;
	D3D11_HS fnCreateHullShader;
} sCreateHullShader_Hook = { 6, NULL };
HRESULT STDMETHODCALLTYPE D3D11_CreateHullShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11HullShader **ppHullShader) {
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	char buffer[80];
	char path[MAX_PATH];

	LogInfo("Create GeometryShader: %016llX\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dumpBin) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-hs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	ID3D11HullShader *pHullShaderNew;
	HRESULT res = sCreateHullShader_Hook.fnCreateHullShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppHullShader);
	if (isCache.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-hs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);
		_crc2 = fnv_64_buf(file.data(), file.size());
		res = sCreateHullShader_Hook.fnCreateHullShader(This, file.data(), file.size(), pClassLinkage, &pHullShaderNew);
	} else if (hasStartPatch.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-hs.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		vector<byte> byteCode(BytecodeLength);
		memcpy(byteCode.data(), pShaderBytecode, BytecodeLength);

		byteCode = assembler(file, byteCode);
		_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
		if (gl_cache_shaders) {
			FILE* f;
			sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-hs.bin", _crc);
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, buffer);

			EnterCriticalSection(&gl_CS);
			fopen_s(&f, path, "wb");
			fwrite(byteCode.data(), 1, byteCode.size(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
		res = sCreateHullShader_Hook.fnCreateHullShader(This, byteCode.data(), byteCode.size(), pClassLinkage, &pHullShaderNew);
	} else if (hasStartFix.count(_crc)) {
		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-hs_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		auto file = readFile(path);

		string shdModel = "hs_5_0";
		ID3DBlob* pByteCode = nullptr;
		ID3DBlob* pErrorMsgs = nullptr;
		HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
			"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
		if (ret == S_OK) {
			_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
			if (gl_cache_shaders) {
				FILE* f;
				sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-hs.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);

				EnterCriticalSection(&gl_CS);
				fopen_s(&f, path, "wb");
				fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			res = sCreateHullShader_Hook.fnCreateHullShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &pHullShaderNew);
		} else {
			LogInfo("compile error:\n%s", path);
		}
	}
	if (*ppHullShader != NULL) {
		shaderMapHS[*ppHullShader] = _crc;
		HSmap[*ppHullShader] = *ppHullShader;
		if (_crc2) {
			crc2[_crc] = _crc2;
			HSmap[*ppHullShader] = pHullShaderNew;
		}
	}
	return res;
}

class DeviceClass {
public:
	DeviceClass(ID3D11Device *This, nv::stereo::ParamTextureManagerD3D11 *TexMgr) {
		mDevice = This;
		mParamTextureManager = TexMgr;
		mStereoHandle = NULL;
		mStereoTexture = NULL;
		mStereoResourceView = NULL;
		mIniTexture = NULL;
		mIniResourceView = NULL;
	}

	ID3D11Device *mDevice;
	StereoHandle mStereoHandle;
	nv::stereo::ParamTextureManagerD3D11 *mParamTextureManager;
	ID3D11Texture2D *mStereoTexture;
	ID3D11ShaderResourceView *mStereoResourceView;
	ID3D11Texture1D *mIniTexture;
	ID3D11ShaderResourceView *mIniResourceView;
};

struct DrawContext {
	bool skip;
	ID3D11PixelShader *oldPixelShader;
	ID3D11VertexShader *oldVertexShader;

	DrawContext() :
		skip(false),
		oldVertexShader(NULL),
		oldPixelShader(NULL)
		 {}
};

map<ID3D11DeviceContext *, DeviceClass *> deviceMap;
map<ID3D11Device *, DeviceClass *> Devices;

vector<UINT64> shaderPixel;
vector<LONGLONG> shaderPixelClock;
vector<UINT64> shaderVertex;
vector<LONGLONG> shaderVertexClock;
UINT64 shaderP = -1;
UINT64 shaderV = -1;

ID3D11DeviceContext * gContext = NULL;
DeviceClass * gDevice = NULL;

typedef void(STDMETHODCALLTYPE* D3D11_GIC)(ID3D11Device * This, ID3D11DeviceContext **ppImmediateContext);
static struct {
	SIZE_T nHookId;
	D3D11_GIC fnGetImmediateContext;
} sGetImmediateContext_Hook = { 14, NULL };
void STDMETHODCALLTYPE D3D11_GetImmediateContext(ID3D11Device * This, ID3D11DeviceContext **ppImmediateContext) {
	sGetImmediateContext_Hook.fnGetImmediateContext(This, ppImmediateContext);
	LogInfo("D3D11_GetImmediateContext, Device: %p, Context: %p\n", This, *ppImmediateContext);
	deviceMap[*ppImmediateContext] = Devices[This];
	hook(ppImmediateContext);
}

#pragma region SetShader
typedef void(STDMETHODCALLTYPE* D3D11C_PSSS)(ID3D11DeviceContext * This, ID3D11PixelShader *pPixelShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_PSSS fnPSSetShader;
} sPSSetShader_Hook = { 15, NULL };
void STDMETHODCALLTYPE D3D11C_PSSetShader(ID3D11DeviceContext * This, ID3D11PixelShader *pPixelShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	currentPS = pPixelShader;
	if (pPixelShader != NULL) {
		UINT64 _crc = shaderMapPS[pPixelShader];
		LogInfo("PSSetShader: %016llX\n", _crc);
		// gl_hunt
		auto itemPos = find(shaderPixel.begin(), shaderPixel.end(), _crc);
		if (itemPos != shaderPixel.end()) {
			auto i = itemPos - shaderPixel.begin();
			shaderPixelClock.erase(shaderPixelClock.begin() + i);
			shaderPixel.erase(itemPos);
		}
		auto tick = GetTickCount64();
		while (shaderPixelClock.size() && *shaderPixelClock.begin() + 5000 < tick) {
			shaderPixel.erase(shaderPixel.begin());
			shaderPixelClock.erase(shaderPixelClock.begin());
		}
		shaderPixel.push_back(_crc);
		shaderPixelClock.push_back(tick);
	}
	sPSSetShader_Hook.fnPSSetShader(This, PSmap[pPixelShader], ppClassInstances, NumClassInstances);
	if (gContext != This) {
		gDevice = deviceMap[This];
		gContext = This;
	}
	This->PSSetShaderResources(125, 1, &gDevice->mStereoResourceView);
	if (gDevice->mIniResourceView != NULL)
		This->PSSetShaderResources(120, 1, &gDevice->mIniResourceView);
}
typedef void(STDMETHODCALLTYPE* D3D11C_VSSS)(ID3D11DeviceContext * This, ID3D11VertexShader *pVertexShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_VSSS fnVSSetShader;
} sVSSetShader_Hook = { 16, NULL };
void STDMETHODCALLTYPE D3D11C_VSSetShader(ID3D11DeviceContext * This, ID3D11VertexShader *pVertexShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	currentVS = pVertexShader;
	if (pVertexShader != NULL) {
		UINT64 _crc = shaderMapVS[pVertexShader];
		LogInfo("VSSetShader: %016llX\n", _crc);
		// gl_hunt
		auto itemPos = find(shaderVertex.begin(), shaderVertex.end(), _crc);
		if (itemPos != shaderVertex.end()) {
			auto i = itemPos - shaderVertex.begin();
			shaderVertexClock.erase(shaderVertexClock.begin() + i);
			shaderVertex.erase(itemPos);
		}
		auto tick = GetTickCount64();
		while (shaderPixelClock.size() && *shaderVertexClock.begin() + 5000 < tick) {
			shaderVertex.erase(shaderVertex.begin());
			shaderVertexClock.erase(shaderVertexClock.begin());
		}
		shaderVertex.push_back(_crc);
		shaderVertexClock.push_back(tick);
	}
	sVSSetShader_Hook.fnVSSetShader(This, VSmap[pVertexShader], ppClassInstances, NumClassInstances);
	if (gContext != This) {
		gDevice = deviceMap[This];
		gContext = This;
	}
	This->VSSetShaderResources(125, 1, &gDevice->mStereoResourceView);
	if (gDevice->mIniResourceView != NULL)
		This->VSSetShaderResources(120, 1, &gDevice->mIniResourceView);
}
typedef void(STDMETHODCALLTYPE* D3D11C_CSSS)(ID3D11DeviceContext * This, ID3D11ComputeShader *pComputeShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_CSSS fnCSSetShader;
} sCSSetShader_Hook = { 17, NULL };
void STDMETHODCALLTYPE D3D11C_CSSetShader(ID3D11DeviceContext * This, ID3D11ComputeShader *pComputeShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	currentCS = pComputeShader;
	if (pComputeShader != NULL) {
		UINT64 _crc = shaderMapCS[pComputeShader];
		LogInfo("CSSetShader: %016llX\n", _crc);
	}
	sCSSetShader_Hook.fnCSSetShader(This, CSmap[pComputeShader], ppClassInstances, NumClassInstances);
	if (gContext != This) {
		gDevice = deviceMap[This];
		gContext = This;
	}
	This->CSSetShaderResources(125, 1, &gDevice->mStereoResourceView);
	if (gDevice->mIniResourceView != NULL)
		This->CSSetShaderResources(120, 1, &gDevice->mIniResourceView);
}
typedef void(STDMETHODCALLTYPE* D3D11C_GSSS)(ID3D11DeviceContext * This, ID3D11GeometryShader *pComputeShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_GSSS fnGSSetShader;
} sGSSetShader_Hook = { 18, NULL };
void STDMETHODCALLTYPE D3D11C_GSSetShader(ID3D11DeviceContext * This, ID3D11GeometryShader *pGeometryShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	currentGS = pGeometryShader;
	if (pGeometryShader != NULL) {
		UINT64 _crc = shaderMapGS[pGeometryShader];
		LogInfo("GSSetShader: %016llX\n", _crc);
	}
	sGSSetShader_Hook.fnGSSetShader(This, GSmap[pGeometryShader], ppClassInstances, NumClassInstances);
	if (gContext != This) {
		gDevice = deviceMap[This];
		gContext = This;
	}
	This->GSSetShaderResources(125, 1, &gDevice->mStereoResourceView);
	if (gDevice->mIniResourceView != NULL)
		This->GSSetShaderResources(120, 1, &gDevice->mIniResourceView);
}
typedef void(STDMETHODCALLTYPE* D3D11C_HSSS)(ID3D11DeviceContext * This, ID3D11HullShader *pHullShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_HSSS fnHSSetShader;
} sHSSetShader_Hook = { 19, NULL };
void STDMETHODCALLTYPE D3D11C_HSSetShader(ID3D11DeviceContext * This, ID3D11HullShader *pHullShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	currentHS = pHullShader;
	if (pHullShader != NULL) {
		UINT64 _crc = shaderMapHS[pHullShader];
		LogInfo("HSSetShader: %016llX\n", _crc);
	}
	sHSSetShader_Hook.fnHSSetShader(This, HSmap[pHullShader], ppClassInstances, NumClassInstances);
	if (gContext != This) {
		gDevice = deviceMap[This];
		gContext = This;
	}
	This->HSSetShaderResources(125, 1, &gDevice->mStereoResourceView);
	if (gDevice->mIniResourceView != NULL)
		This->HSSetShaderResources(120, 1, &gDevice->mIniResourceView);
}
typedef void(STDMETHODCALLTYPE* D3D11C_DSSS)(ID3D11DeviceContext * This, ID3D11DomainShader *pDomainShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_DSSS fnDSSetShader;
} sDSSetShader_Hook = { 20, NULL };
void STDMETHODCALLTYPE D3D11C_DSSetShader(ID3D11DeviceContext * This, ID3D11DomainShader *pDomainShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	currentDS = pDomainShader;
	if (pDomainShader != NULL) {
		UINT64 _crc = shaderMapDS[pDomainShader];
		LogInfo("DSSetShader: %016llX\n", _crc);
	}
	sDSSetShader_Hook.fnDSSetShader(This, DSmap[pDomainShader], ppClassInstances, NumClassInstances);
	if (gContext != This) {
		gDevice = deviceMap[This];
		gContext = This;
	}
	This->DSSetShaderResources(125, 1, &gDevice->mStereoResourceView);
	if (gDevice->mIniResourceView != NULL)
		This->DSSetShaderResources(120, 1, &gDevice->mIniResourceView);
}
#pragma endregion

#pragma region draw
set<UINT64> skip;
void ProcessShaderOverride(bool isPixelShader, DrawContext *data) {
	UINT64 _crc;
	bool use_orig = false;
	if (isPixelShader && currentPS) {
		_crc = shaderMapPS[currentPS];
		if (_crc == shaderP)
			data->skip = true;
		if (skip.count(_crc))
			data->skip = true;
	}
	if (!isPixelShader && currentVS) {
		_crc = shaderMapVS[currentVS];
		if (_crc == shaderV)
			data->skip = true;
		if (skip.count(_crc))
			data->skip = true;
	}
}
typedef void(STDMETHODCALLTYPE* D3D11C_Draw)(ID3D11DeviceContext * This, UINT VertexCount, UINT StartVertexLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_Draw fnDraw;
} sDraw_Hook = { 7, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawAuto)(ID3D11DeviceContext * This);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawAuto fnDrawAuto;
} sDrawAuto_Hook = { 8, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawIndexed)(ID3D11DeviceContext * This, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawIndexed fnDrawIndexed;
} sDrawIndexed_Hook = { 9, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawInstanced)(ID3D11DeviceContext * This, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawInstanced fnDrawInstanced;
} sDrawInstanced_Hook = { 10, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawIndexedInstanced)(ID3D11DeviceContext * This, UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawIndexedInstanced fnDrawIndexedInstanced;
} sDrawIndexedInstanced_Hook = { 11, NULL };
DrawContext BeforeDraw() {
	DrawContext data;

	if (!gl_fix_enabled)
		return data;

	ProcessShaderOverride(true, &data);
	ProcessShaderOverride(false, &data);
	return data;
}
void AfterDraw(DrawContext &data) {
	if (data.skip)
		return;
}
void STDMETHODCALLTYPE D3D11H_Draw(ID3D11DeviceContext * This, UINT VertexCount, UINT StartVertexLocation) {
	auto c = BeforeDraw();
	if (!c.skip)
		sDraw_Hook.fnDraw(This, VertexCount, StartVertexLocation);
	AfterDraw(c);
}
void STDMETHODCALLTYPE D3D11H_DrawAuto(ID3D11DeviceContext * This) {
	auto c = BeforeDraw();
	if (!c.skip)
		sDrawAuto_Hook.fnDrawAuto(This);
	AfterDraw(c);
}
void STDMETHODCALLTYPE D3D11H_DrawIndexed(ID3D11DeviceContext * This, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation) {
	auto c = BeforeDraw();
	if (!c.skip)
		sDrawIndexed_Hook.fnDrawIndexed(This, IndexCount, StartIndexLocation, BaseVertexLocation);
	AfterDraw(c);
}
void STDMETHODCALLTYPE D3D11H_DrawInstanced(ID3D11DeviceContext * This, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation) {
	auto c = BeforeDraw();
	if (!c.skip)
		sDrawInstanced_Hook.fnDrawInstanced(This, VertexCountPerInstance, InstanceCount, StartVertexLocation, StartInstanceLocation);
	AfterDraw(c);
}
void STDMETHODCALLTYPE D3D11H_DrawIndexedInstanced(ID3D11DeviceContext * This, UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation) {
	auto c = BeforeDraw();
	if (!c.skip)
		sDrawIndexedInstanced_Hook.fnDrawIndexedInstanced(This, IndexCountPerInstance, InstanceCount, StartIndexLocation, BaseVertexLocation, StartInstanceLocation);
	AfterDraw(c);
}
#pragma endregion

#pragma region buttons
enum buttonPress { Unchanged, Down, Up };

class button {
public:
	virtual buttonPress buttonCheck() = 0;
};

class keyboardMouseKey : public button {
public:
	keyboardMouseKey(string s) {
		VKey = ParseVKey(s.c_str());
		oldState = 0;
	}
	buttonPress buttonCheck() {
		SHORT state = GetAsyncKeyState(VKey);
		buttonPress status = buttonPress::Unchanged;
		if ((state & 0x8000) && !(oldState & 0x8000)) {
			status = buttonPress::Down;
		}
		if (!(state & 0x8000) && (oldState & 0x8000)) {
			status = buttonPress::Up;
		}
		oldState = state;
		return status;
	}
private:
	SHORT oldState;
	int VKey;
};

WORD getXInputButton(const char* button) {
	if (_stricmp(button, "A") == 0)
		return XINPUT_GAMEPAD_A;
	if (_stricmp(button, "B") == 0)
		return XINPUT_GAMEPAD_B;
	if (_stricmp(button, "X") == 0)
		return XINPUT_GAMEPAD_X;
	if (_stricmp(button, "Y") == 0)
		return XINPUT_GAMEPAD_Y;
	if (_stricmp(button, "START") == 0)
		return XINPUT_GAMEPAD_START;
	if (_stricmp(button, "BACK") == 0)
		return XINPUT_GAMEPAD_BACK;
	if (_stricmp(button, "DPAD_RIGHT") == 0)
		return XINPUT_GAMEPAD_DPAD_RIGHT;
	if (_stricmp(button, "DPAD_LEFT") == 0)
		return XINPUT_GAMEPAD_DPAD_LEFT;
	if (_stricmp(button, "DPAD_UP") == 0)
		return XINPUT_GAMEPAD_DPAD_UP;
	if (_stricmp(button, "DPAD_DOWN") == 0)
		return XINPUT_GAMEPAD_DPAD_DOWN;
	if (_stricmp(button, "RIGHT_SHOULDER") == 0)
		return XINPUT_GAMEPAD_RIGHT_SHOULDER;
	if (_stricmp(button, "LEFT_SHOULDER") == 0)
		return XINPUT_GAMEPAD_LEFT_SHOULDER;
	if (_stricmp(button, "RIGHT_THUMB") == 0)
		return XINPUT_GAMEPAD_RIGHT_THUMB;
	if (_stricmp(button, "LEFT_THUMB") == 0)
		return XINPUT_GAMEPAD_LEFT_THUMB;
	if (_stricmp(button, "LEFT_TRIGGER") == 0)
		return 0x400;
	if (_stricmp(button, "RIGHT_TRIGGER") == 0)
		return 0x800;
	return 0;
}

class xboxKey : public button {
public:
	xboxKey(string s) {
		if (s[2] == '_') {
			c = 0;
			XKey = getXInputButton(s.c_str() + 3);
		} else {
			c = s[2] - '0' - 1;
			XKey = getXInputButton(s.c_str() + 4);
		}
		ZeroMemory(&oldState, sizeof(XINPUT_STATE));
		XInputGetState(c, &oldState);
	}
	buttonPress buttonCheck() {
		buttonPress status = buttonPress::Unchanged;
		XINPUT_STATE state;
		ZeroMemory(&state, sizeof(XINPUT_STATE));
		XInputGetState(c, &state);
		if (XKey == 0x400) {
			if (state.Gamepad.bLeftTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD && oldState.Gamepad.bLeftTrigger <= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
				status = buttonPress::Down;
			if (state.Gamepad.bLeftTrigger < XINPUT_GAMEPAD_TRIGGER_THRESHOLD && oldState.Gamepad.bLeftTrigger >= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
				status = buttonPress::Up;
		} else if (XKey == 0x800) {
			if (state.Gamepad.bRightTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD && oldState.Gamepad.bRightTrigger <= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
				status = buttonPress::Down;;
			if (state.Gamepad.bRightTrigger < XINPUT_GAMEPAD_TRIGGER_THRESHOLD && oldState.Gamepad.bRightTrigger >= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
				status = buttonPress::Up;
		} else {
			if (state.Gamepad.wButtons & XKey && !(oldState.Gamepad.wButtons & XKey))
				status = buttonPress::Down;
			if (!(state.Gamepad.wButtons & XKey) && oldState.Gamepad.wButtons & XKey)
				status = buttonPress::Up;
		}
		oldState = state;
		return status;
	}
private:
	XINPUT_STATE oldState;
	WORD XKey;
	int c;
};

button* createButton(string key) {
	if (_strnicmp(key.c_str(), "XB", 2) == 0) {
		return new xboxKey(key);
	} else {
		return new keyboardMouseKey(key);
	}
}

vector<UINT64> frameV;
vector<UINT64> frameP;
auto frameVpos = frameV.rend();
auto framePpos = frameP.rend();

void HuntBeep() {
	Beep(440, 200);
}

void reloadFixes() {
	WIN32_FIND_DATA findFileData;
	char path[MAX_PATH];
	char buffer[80];

	path[0] = 0;
	strcat_s(path, MAX_PATH, cwd);
	strcat_s(path, MAX_PATH, "\\ShaderFixes\\????????????????-??.txt");
	HANDLE hFind = FindFirstFile(path, &findFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			string s = findFileData.cFileName;
			string sHash = s.substr(0, 16);
			UINT64 _crc = stoull(sHash, NULL, 16);
			if (crc2.count(_crc))
				crc2[_crc] = crc2[_crc];
			else
				crc2[_crc] = _crc;
		} while (FindNextFile(hFind, &findFileData));
		FindClose(hFind);
	}
	for (auto i = crc2.begin(); i != crc2.end(); i++) {
		bool missing = true;
		UINT64 _crc = i->first;

		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		vector<byte> file = readFile(path);
		if (file.size() > 0) {
			missing = false;
			vector<byte> byteCode = *origShaderData[_crc];

			byteCode = assembler(file, byteCode);
			UINT64 _crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
			if (i->second != _crc2) {
				crc2[_crc] = _crc2;

				ID3D11PixelShader* pPixelShader = NULL;
				HRESULT res = sCreatePixelShader_Hook.fnCreatePixelShader(gDevice->mDevice, byteCode.data(), byteCode.size(), NULL, &pPixelShader);
				for (auto j = shaderMapPS.begin(); j != shaderMapPS.end(); j++) {
					if (j->second == _crc) {
						if (PSmap[j->first] != j->first)
							PSmap[j->first]->Release();
						PSmap[j->first] = pPixelShader;
						break;
					}
				}

				if (gl_cache_shaders) {
					FILE* f;
					sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.bin", _crc);
					path[0] = 0;
					strcat_s(path, MAX_PATH, cwd);
					strcat_s(path, MAX_PATH, buffer);

					EnterCriticalSection(&gl_CS);
					fopen_s(&f, path, "wb");
					fwrite(byteCode.data(), 1, byteCode.size(), f);
					fclose(f);
					LeaveCriticalSection(&gl_CS);
				}
			}
		}

		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		file = readFile(path);
		if (file.size() > 0) {
			missing = false;
			vector<byte> byteCode = *origShaderData[_crc];

			byteCode = assembler(file, byteCode);
			UINT64 _crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
			if (i->second != _crc2) {
				crc2[_crc] = _crc2;

				ID3D11VertexShader* pVertexShader = NULL;
				HRESULT res = sCreateVertexShader_Hook.fnCreateVertexShader(gDevice->mDevice, byteCode.data(), byteCode.size(), NULL, &pVertexShader);
				for (auto j = shaderMapVS.begin(); j != shaderMapVS.end(); j++) {
					if (j->second == _crc) {
						if (VSmap[j->first] != j->first)
							VSmap[j->first]->Release();
						VSmap[j->first] = pVertexShader;
						break;
					}
				}

				if (gl_cache_shaders) {
					FILE* f;
					sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.bin", _crc);
					path[0] = 0;
					strcat_s(path, MAX_PATH, cwd);
					strcat_s(path, MAX_PATH, buffer);

					EnterCriticalSection(&gl_CS);
					fopen_s(&f, path, "wb");
					fwrite(byteCode.data(), 1, byteCode.size(), f);
					fclose(f);
					LeaveCriticalSection(&gl_CS);
				}
			}
		}

		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		file = readFile(path);
		if (file.size() > 0) {
			missing = false;
			string shdModel = "vs_5_0";
			ID3DBlob* pByteCode = nullptr;
			ID3DBlob* pErrorMsgs = nullptr;
			HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
				"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
			if (ret == S_OK) {
				UINT64 _crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
				if (i->second != _crc2) {
					crc2[_crc] = _crc2;

					ID3D11VertexShader* pVertexShader = NULL;
					HRESULT res = sCreateVertexShader_Hook.fnCreateVertexShader(gDevice->mDevice, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), NULL, &pVertexShader);
					for (auto j = shaderMapVS.begin(); j != shaderMapVS.end(); j++) {
						if (j->second == _crc) {
							if (VSmap[j->first] != j->first)
								VSmap[j->first]->Release();
							VSmap[j->first] = pVertexShader;
							break;
						}
					}

					if (gl_cache_shaders) {
						FILE* f;
						sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.bin", _crc);
						path[0] = 0;
						strcat_s(path, MAX_PATH, cwd);
						strcat_s(path, MAX_PATH, buffer);

						EnterCriticalSection(&gl_CS);
						fopen_s(&f, path, "wb");
						fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
						fclose(f);
						LeaveCriticalSection(&gl_CS);
					}
				}
			}
		}

		sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps_replace.txt", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);
		file = readFile(path);
		if (file.size() > 0) {
			missing = false;
			string shdModel = "ps_5_0";
			ID3DBlob* pByteCode = nullptr;
			ID3DBlob* pErrorMsgs = nullptr;
			HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
				"main", shdModel.c_str(), D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
			if (ret == S_OK) {
				UINT64 _crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
				if (i->second != _crc2) {
					crc2[_crc] = _crc2;

					ID3D11PixelShader* pPixelShader = NULL;
					HRESULT res = sCreatePixelShader_Hook.fnCreatePixelShader(gDevice->mDevice, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), NULL, &pPixelShader);
					for (auto j = shaderMapPS.begin(); j != shaderMapPS.end(); j++) {
						if (j->second == _crc) {
							if (PSmap[j->first] != j->first)
								PSmap[j->first]->Release();
							PSmap[j->first] = pPixelShader;
							break;
						}
					}

					if (gl_cache_shaders) {
						FILE* f;
						sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.bin", _crc);
						path[0] = 0;
						strcat_s(path, MAX_PATH, cwd);
						strcat_s(path, MAX_PATH, buffer);

						EnterCriticalSection(&gl_CS);
						fopen_s(&f, path, "wb");
						fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
						fclose(f);
						LeaveCriticalSection(&gl_CS);
					}
				}
			}
		}
		if (missing) {
			vector<byte> byteCode = *origShaderData[_crc];
			string shdModel = shaderModel(byteCode.data());
			crc2.erase(_crc);
			if (!strncmp(shdModel.c_str(), "ps", 2)) {
				for (auto j = shaderMapPS.begin(); j != shaderMapPS.end(); j++) {
					if (j->second == _crc) {
						if (PSmap[j->first] != j->first)
							PSmap[j->first]->Release();
						PSmap[j->first] = j->first;
						break;
					}
				}

				if (gl_cache_shaders) {
					sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-ps.bin", _crc);
					path[0] = 0;
					strcat_s(path, MAX_PATH, cwd);
					strcat_s(path, MAX_PATH, buffer);
					DeleteFile(path);
				}
			} else {
				for (auto j = shaderMapVS.begin(); j != shaderMapVS.end(); j++) {
					if (j->second == _crc) {
						if (VSmap[j->first] != j->first)
							VSmap[j->first]->Release();
						VSmap[j->first] = j->first;
						break;
					}
				}

				if (gl_cache_shaders) {
					sprintf_s(buffer, 80, "\\ShaderFixes\\%016llX-vs.bin", _crc);
					path[0] = 0;
					strcat_s(path, MAX_PATH, cwd);
					strcat_s(path, MAX_PATH, buffer);
					DeleteFile(path);
				}
			}
		}
	}
	HuntBeep();
}

class HuntButtonHandler {
public:
	HuntButtonHandler(button* b, string command) {
		Button = b;
		Command = command;
	}
	void Handle() {
		buttonPress status = Button->buttonCheck();
		char path[MAX_PATH];
		FILE* f;

		if (status == buttonPress::Down && gl_hunt) {
			if (shaderP == -1) {
				frameP.resize(shaderPixel.size());
				copy(shaderPixel.begin(), shaderPixel.end(), frameP.begin());
				framePpos = frameP.rend();
			}
			if (shaderV == -1) {
				frameV.resize(shaderVertex.size());
				copy(shaderVertex.begin(), shaderVertex.end(), frameV.begin());
				frameVpos = frameV.rend();
			}
			if (!strcmp(Command.c_str(), "next_pixelshader")) {
				if (framePpos == frameP.rend()) {
					framePpos = frameP.rbegin();
					shaderP = *framePpos;
				} else {
					framePpos++;
					if (framePpos == frameP.rend()) {
						shaderP = -1;
						HuntBeep();
					} else {
						shaderP = *framePpos;
					}
				}
			}
			if (!strcmp(Command.c_str(), "previous_pixelshader")) {
				if (framePpos == frameP.rend()) {
					shaderP = -1;
					HuntBeep();
				} else if (framePpos == frameP.rbegin()) {
					shaderP = -1;
					HuntBeep();
					framePpos = frameP.rend();
				} else {
					--framePpos;
					shaderP = *framePpos;
				}
			}
			if (!strcmp(Command.c_str(), "mark_pixelshader") && shaderP != -1) {
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, "\\Mark");
				CreateDirectory(path, NULL);

				auto _crc = shaderP;
				char buffer[80];
				sprintf_s(buffer, 80, "\\Mark\\%016llX-ps.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);
				fopen_s(&f, path, "wb");

				EnterCriticalSection(&gl_CS);
				vector<byte> * v = origShaderData[_crc];
				fwrite(v->data(), 1, v->size(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			if (!strcmp(Command.c_str(), "next_vertexshader")) {
				if (frameVpos == frameV.rend()) {
					frameVpos = frameV.rbegin();
					shaderV = *frameVpos;
				} else {
					frameVpos++;
					if (frameVpos == frameV.rend()) {
						shaderV = -1;
						HuntBeep();
					} else {
						shaderV = *frameVpos;
					}
				}
			}
			if (!strcmp(Command.c_str(), "previous_vertexshader")) {
				if (frameVpos == frameV.rend()) {
					shaderV = -1;
					HuntBeep();
				} else if (frameVpos == frameV.rbegin()) {
					shaderV = -1;
					HuntBeep();
					frameVpos = frameV.rend();
				} else {
					--frameVpos;
					shaderV = *frameVpos;
				}
			}
			if (!strcmp(Command.c_str(), "mark_vertexshader") && shaderV != -1) {
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, "\\Mark");
				CreateDirectory(path, NULL);

				auto _crc = shaderV;
				char buffer[80];
				sprintf_s(buffer, 80, "\\Mark\\%016llX-vs.bin", _crc);
				path[0] = 0;
				strcat_s(path, MAX_PATH, cwd);
				strcat_s(path, MAX_PATH, buffer);
				fopen_s(&f, path, "wb");

				EnterCriticalSection(&gl_CS);
				vector<byte> * v = origShaderData[_crc];
				fwrite(v->data(), 1, v->size(), f);
				fclose(f);
				LeaveCriticalSection(&gl_CS);
			}
			if (!strcmp(Command.c_str(), "reload_fixes")) {
				reloadFixes();
				InitShaders();
			}
		}
		if (gl_hunt && status == buttonPress::Down && !strcmp(Command.c_str(), "show_original")) {
			gl_fix_enabled = false;
		}
		if (gl_hunt && status == buttonPress::Up && !strcmp(Command.c_str(), "show_original")) {
			gl_fix_enabled = true;
		}
		if (status == buttonPress::Down && !strcmp(Command.c_str(), "toggle_hunting")) {
			shaderP = -1;
			shaderV = -1;
			gl_hunt = !gl_hunt;
			HuntBeep();
		}
	}
	string Command;
	button* Button;
};
vector<HuntButtonHandler*> hBHs;

string& trim(string& str)
{
	str.erase(str.begin(), find_if(str.begin(), str.end(),
		[](char& ch)->bool { return !isspace(ch); }));
	str.erase(find_if(str.rbegin(), str.rend(),
		[](char& ch)->bool { return !isspace(ch); }).base(), str.end());
	return str;
}

enum KeyType { Activate, Hold, Toggle, Cycle };
enum TransitionType { Linear, Cosine };

class ButtonHandler {
public:
	ButtonHandler(button* b, KeyType type, int variable, vector<string> value, TransitionType tt, TransitionType rtt) {
		Button = b;
		Type = type;
		Variable = variable;
		TT = tt;
		rTT = rtt;

		delay = 0;
		transition = 0;
		releaseDelay = 0;
		releaseTransition = 0;

		cyclePosition = 0;
		Value = { FLT_MAX, FLT_MAX, FLT_MAX, FLT_MAX, FLT_MAX, FLT_MAX };
		if (Type == KeyType::Cycle) {
			for (int i = 0; i < 8; i++) {
				LogInfo("%s\n", value[i].c_str());
				if (variable & 1 << i) {
					vector<float> store;
					while (true) {
						int pos = value[i].find(',');
						if (pos == value[i].npos) {
							string val = value[i];
							val = trim(val);
							if (val.size() == 0) {
								store.push_back(FLT_MAX);
							} else {
								store.push_back(stof(val));
							}
							break;
						} else {
							string val = value[i].substr(0, pos);
							val = trim(val);
							if (val.size() == 0) {
								store.push_back(FLT_MAX);
							} else {
								store.push_back(stof(val));
							}
							value[i] = value[i].substr(pos + 1);
						}
					}
					mArray.push_back(store);
				} else {
					vector<float> store;
					store.push_back(FLT_MAX);
					mArray.push_back(store);
				}
			}
			for (int i = 0; i < 8; i++) {
				maxSize = max(maxSize, mArray[i].size());
			}
			for (int i = 0; i < 8; i++) {
				if (maxSize > mArray[i].size()) {
					for (int j = mArray[i].size(); j < maxSize; j++) {
						mArray[i].push_back(mArray[i][j - 1]);
					}
				}
			}
			initializeDelay(cyclePosition);
		} else {
			if (variable & 0x001) Value[0] = stof(value[0]);
			if (variable & 0x002) Value[1] = stof(value[1]);
			if (variable & 0x004) Value[2] = stof(value[2]);
			if (variable & 0x008) Value[3] = stof(value[3]);
			if (variable & 0x010) Value[4] = stof(value[4]);
			if (variable & 0x020) Value[5] = stof(value[5]);
			if (variable & 0x040) delay = stol(value[6]);
			if (variable & 0x080) transition = stol(value[7]);
			if (variable & 0x100) releaseDelay = stol(value[8]);
			if (variable & 0x200) releaseTransition = stol(value[9]);
		}
		SavedValue = readINI();
		toggleDown = true;

		curDelay = 0;
		curDelayUp = 0;
		curTransition = 0;
		curTransitionUp = 0;
	}
	void initializeDelay(int c) {
		delay = 0;
		if (mArray[6][c] != FLT_MAX)
			delay = mArray[6][c];
	}
	void initializeCycle(int c) {
		Variable = 0;
		for (int i = 0; i < 6; i++) {
			if (mArray[i][c] != FLT_MAX) {
				Variable |= 1 << i;
				Value[i] = mArray[i][c];
			}
		}
		transition = 0;
		if (mArray[7][c] != FLT_MAX)
			transition = mArray[7][c];
	}
	void Handle() {
		buttonPress status = Button->buttonCheck();

		if (status == buttonPress::Down) {
			if (delay > 0) {
				curDelay = GetTickCount64() + delay;
			} else {
				buttonDown();
			}
		}
		if (status == buttonPress::Up) {
			if (releaseDelay > 0) {
				curDelayUp = GetTickCount64() + releaseDelay;
			} else {
				buttonUp();
			}
		}

		if (delay > 0 && curDelay > 0 && GetTickCount64() > curDelay) {
			buttonDown();
			curDelay = 0;
		}
		if (releaseDelay > 0 && curDelayUp > 0 && GetTickCount64() > curDelayUp) {
			buttonUp();
			curDelayUp = 0;
		}
		if (transition > 0 && curTransition > 0) {
			if (GetTickCount64() > curTransition) {
				setVariable(transitionVariable(transition, curTransition, TT));
				curTransition = 0;
			} else {
				ULONGLONG newTick = GetTickCount64();
				if (newTick != lastTick) {
					setVariable(transitionVariable(transition, curTransition, TT));
					lastTick = newTick;
				}
			}
		}
		if (releaseTransition > 0 && curTransitionUp > 0) {
			if (GetTickCount64() > curTransitionUp) {
				setVariable(transitionVariable(releaseTransition, curTransitionUp, rTT));
				curTransitionUp = 0;
			} else {
				ULONGLONG newTick = GetTickCount64();
				if (newTick != lastTick) {
					setVariable(transitionVariable(releaseTransition, curTransitionUp, rTT));
					lastTick = newTick;
				}
			}
		}
	}
private:
	void buttonUp() {
		if (Type == KeyType::Hold) {
			sT = readVariable();
			Store = SavedValue;
			if (curDelay > 0)
				curDelay = 0; // cancel delayed keypress
			if (curTransition > 0)
				curTransition = 0; // cancel transition
			if (releaseTransition > 0) {
				lastTick = GetTickCount64();
				curTransitionUp = lastTick + releaseTransition;
			} else {
				setVariable(Store);
			}
		}
	}
	void buttonDown() {
		sT = readVariable();
		if (Type == KeyType::Toggle) {
			if (toggleDown) {
				SavedValue = readStereo(SavedValue);
				toggleDown = false;
				Store = Value;
			} else {
				toggleDown = true;
				Store = SavedValue;
			}
		} else if (Type == KeyType::Hold) {
			if (curDelayUp > 0)
				curDelayUp = 0; // cancel delayed keypress
			if (curTransitionUp > 0)
				curTransitionUp = 0; // cancel transition
			SavedValue = readStereo(SavedValue);
			Store = Value;
		} else if (Type == KeyType::Activate) {
			Store = Value;
		} else if (Type == KeyType::Cycle) {
			initializeCycle(cyclePosition++);
			if (cyclePosition == maxSize)
				cyclePosition = 0;
			initializeDelay(cyclePosition);
			Store = Value;
		}
		if (transition > 0) {
			lastTick = GetTickCount64();
			curTransition = lastTick + transition;
		} else {
			setVariable(Store);
		}
	}
	vector<float> transitionVariable(ULONGLONG transition, ULONGLONG curTransition, TransitionType tt) {
		vector<float> f(6);
		ULONGLONG transitionAmount = transition;
		if (GetTickCount64() < curTransition) {
			transitionAmount = transition - (curTransition - GetTickCount64());
		}
		float percentage = transitionAmount / (float)transition;
		if (tt == TransitionType::Cosine)
			percentage = (1 - cos(percentage * M_PI)) / 2;
		if (Variable & 0x01) f[0] = sT[0] + (Store[0] - sT[0]) * percentage;
		if (Variable & 0x02) f[1] = sT[1] + (Store[1] - sT[1]) * percentage;
		if (Variable & 0x04) f[2] = sT[2] + (Store[2] - sT[2]) * percentage;
		if (Variable & 0x08) f[3] = sT[3] + (Store[3] - sT[3]) * percentage;
		if (Variable & 0x10) f[4] = sT[4] + (Store[4] - sT[4]) * percentage;
		if (Variable & 0x20) f[5] = sT[5] + (Store[5] - sT[5]) * percentage;
		return f;
	}
	vector<float> readVariable() {
		vector<float> f(6);
		if (Variable & 0x01) f[0] = iniParams.x;
		if (Variable & 0x02) f[1] = iniParams.y;
		if (Variable & 0x04) f[2] = iniParams.z;
		if (Variable & 0x08) f[3] = iniParams.w;
		if (Variable & 0x10) NvAPI_Stereo_GetConvergence(gDevice->mStereoHandle, &f[4]);
		if (Variable & 0x20) NvAPI_Stereo_GetSeparation(gDevice->mStereoHandle, &f[5]);
		return f;
	}
	vector<float> readINI() {
		vector<float> f(6);
		if (Variable & 0x01) f[0] = iniParams.x;
		if (Variable & 0x02) f[1] = iniParams.y;
		if (Variable & 0x04) f[2] = iniParams.z;
		if (Variable & 0x08) f[3] = iniParams.w;
		return f;
	}
	vector<float> readStereo(vector<float> f) {
		if (Variable & 0x10) NvAPI_Stereo_GetConvergence(gDevice->mStereoHandle, &f[4]);
		if (Variable & 0x20) NvAPI_Stereo_GetSeparation(gDevice->mStereoHandle, &f[5]);
		return f;
	}
	void setVariable(vector<float> f) {
		if (Variable & 0x01) iniParams.x = f[0];
		if (Variable & 0x02) iniParams.y = f[1];
		if (Variable & 0x04) iniParams.z = f[2];
		if (Variable & 0x08) iniParams.w = f[3];
		if (Variable & 0x10) NvAPI_Stereo_SetConvergence(gDevice->mStereoHandle, f[4]);
		if (Variable & 0x20) NvAPI_Stereo_SetSeparation(gDevice->mStereoHandle, f[5]);
		if (Variable & 0x0F) {
			D3D11_MAPPED_SUBRESOURCE mappedResource;
			gContext->Map(gDevice->mIniTexture, 0, D3D11_MAP_WRITE_DISCARD, 0, &mappedResource);
			memcpy(mappedResource.pData, &iniParams, sizeof(iniParams));
			gContext->Unmap(gDevice->mIniTexture, 0);
		}
	}
	button* Button;
	KeyType Type;
	// Variable Flags
	// 1 INIParams.x
	// 2 INIParams.y
	// 4 INIParams.z
	// 8 INIParams.w
	// 16 Convergence
	// 32 Separation
	int Variable;
	TransitionType TT;
	TransitionType rTT;
	vector<float> Value;
	vector<float> SavedValue;
	vector<float> Store;
	vector<float> sT; // start transition
	ULONGLONG lastTick;

	ULONGLONG delay;
	ULONGLONG releaseDelay;
	ULONGLONG curDelay;
	ULONGLONG curDelayUp;

	ULONGLONG transition;
	ULONGLONG releaseTransition;
	ULONGLONG curTransition;
	ULONGLONG curTransitionUp;
	bool toggleDown;
	int cyclePosition;
	vector<vector<float>> mArray;
	int maxSize = 0;
};

vector<ButtonHandler*> BHs;

void frameFunction() {
	for (size_t i = 0; i < BHs.size(); i++) {
		BHs[i]->Handle();
	}
	for (size_t i = 0; i < hBHs.size(); i++) {
		hBHs[i]->Handle();
	}
}
#pragma endregion

#pragma region hook
void hook(ID3D11DeviceContext** ppContext) {
	if (ppContext != NULL && *ppContext != NULL) {
		LogInfo("Hook  Context: %p\n", *ppContext);
		if (!gl_hookedContext) {
			LogInfo("Hook attatched\n");
			DWORD_PTR*** vTable = (DWORD_PTR***)*ppContext;
			D3D11C_PSSS origPSSS = (D3D11C_PSSS)(*vTable)[9];
			D3D11C_VSSS origVSSS = (D3D11C_VSSS)(*vTable)[11];
			D3D11C_GSSS origGSSS = (D3D11C_GSSS)(*vTable)[23];
			D3D11C_HSSS origHSSS = (D3D11C_HSSS)(*vTable)[60];
			D3D11C_DSSS origDSSS = (D3D11C_DSSS)(*vTable)[64];
			D3D11C_CSSS origCSSS = (D3D11C_CSSS)(*vTable)[69];

			D3D11C_Draw origDraw = (D3D11C_Draw)(*vTable)[13];
			D3D11C_DrawAuto origDrawAuto = (D3D11C_DrawAuto)(*vTable)[38];
			D3D11C_DrawIndexed origDrawIndexed = (D3D11C_DrawIndexed)(*vTable)[12];
			D3D11C_DrawInstanced origDrawInstanced = (D3D11C_DrawInstanced)(*vTable)[21];
			D3D11C_DrawIndexedInstanced origDrawIndexedInstanced = (D3D11C_DrawIndexedInstanced)(*vTable)[20];

			cHookMgr.Hook(&(sPSSetShader_Hook.nHookId), (LPVOID*)&(sPSSetShader_Hook.fnPSSetShader), origPSSS, D3D11C_PSSetShader);
			cHookMgr.Hook(&(sVSSetShader_Hook.nHookId), (LPVOID*)&(sVSSetShader_Hook.fnVSSetShader), origVSSS, D3D11C_VSSetShader);
			cHookMgr.Hook(&(sGSSetShader_Hook.nHookId), (LPVOID*)&(sGSSetShader_Hook.fnGSSetShader), origGSSS, D3D11C_GSSetShader);
			cHookMgr.Hook(&(sHSSetShader_Hook.nHookId), (LPVOID*)&(sHSSetShader_Hook.fnHSSetShader), origHSSS, D3D11C_HSSetShader);
			cHookMgr.Hook(&(sDSSetShader_Hook.nHookId), (LPVOID*)&(sDSSetShader_Hook.fnDSSetShader), origDSSS, D3D11C_DSSetShader);
			cHookMgr.Hook(&(sCSSetShader_Hook.nHookId), (LPVOID*)&(sCSSetShader_Hook.fnCSSetShader), origCSSS, D3D11C_CSSetShader);

			cHookMgr.Hook(&(sDraw_Hook.nHookId), (LPVOID*)&(sDraw_Hook.fnDraw), origDraw, D3D11H_Draw);
			cHookMgr.Hook(&(sDrawAuto_Hook.nHookId), (LPVOID*)&(sDrawAuto_Hook.fnDrawAuto), origDrawAuto, D3D11H_DrawAuto);
			cHookMgr.Hook(&(sDrawIndexed_Hook.nHookId), (LPVOID*)&(sDrawIndexed_Hook.fnDrawIndexed), origDrawIndexed, D3D11H_DrawIndexed);
			cHookMgr.Hook(&(sDrawInstanced_Hook.nHookId), (LPVOID*)&(sDrawInstanced_Hook.fnDrawInstanced), origDrawInstanced, D3D11H_DrawInstanced);
			cHookMgr.Hook(&(sDrawIndexedInstanced_Hook.nHookId), (LPVOID*)&(sDrawIndexedInstanced_Hook.fnDrawIndexedInstanced), origDrawIndexedInstanced, D3D11H_DrawIndexedInstanced);

			gl_hookedContext = true;
		}
	}
}

HRESULT CreateStereoParamTextureAndView(ID3D11Device* d3d11)
{
	// This function creates a texture that is suitable to be stereoized by the driver.
	// Note that the parameters primarily come from nvstereo.h
	using nv::stereo::ParamTextureManagerD3D11;

	HRESULT hr = 0;

	D3D11_TEXTURE2D_DESC desc;
	desc.Width = ParamTextureManagerD3D11::Parms::StereoTexWidth;
	desc.Height = ParamTextureManagerD3D11::Parms::StereoTexHeight;
	desc.MipLevels = 1;
	desc.ArraySize = 1;
	desc.Format = ParamTextureManagerD3D11::Parms::StereoTexFormat;
	desc.SampleDesc.Count = 1;
	desc.SampleDesc.Quality = 0;
	desc.Usage = D3D11_USAGE_DYNAMIC;
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
	desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;
	desc.MiscFlags = 0;
	d3d11->CreateTexture2D(&desc, NULL, &Devices[d3d11]->mStereoTexture);

	// Since we need to bind the texture to a shader input, we also need a resource view.
	D3D11_SHADER_RESOURCE_VIEW_DESC descRV;
	descRV.Format = desc.Format;
	descRV.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
	descRV.Texture2D.MipLevels = 1;
	descRV.Texture2D.MostDetailedMip = 0;
	descRV.Texture2DArray.MostDetailedMip = 0;
	descRV.Texture2DArray.MipLevels = 1;
	descRV.Texture2DArray.FirstArraySlice = 0;
	descRV.Texture2DArray.ArraySize = desc.ArraySize;
	d3d11->CreateShaderResourceView(Devices[d3d11]->mStereoTexture, &descRV, &Devices[d3d11]->mStereoResourceView);

	return S_OK;
}

void CreateINITexture(ID3D11Device* d3d11) {
	if (iniParams.x != FLT_MAX || iniParams.y != FLT_MAX || iniParams.z != FLT_MAX || iniParams.w != FLT_MAX) {
		D3D11_TEXTURE1D_DESC desc;
		memset(&desc, 0, sizeof(D3D11_TEXTURE1D_DESC));
		D3D11_SUBRESOURCE_DATA initialData;
		initialData.pSysMem = &iniParams;
		initialData.SysMemPitch = sizeof(DirectX::XMFLOAT4) * 1;	// only one 4 element struct

		desc.Width = 1;												// 1 texel, .rgba as a float4
		desc.MipLevels = 1;
		desc.ArraySize = 1;
		desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;	// float4
		desc.Usage = D3D11_USAGE_DYNAMIC;				// Read/Write access from GPU and CPU
		desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;		// As resource view, access via t120
		desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;		// allow CPU access for hotkeys
		desc.MiscFlags = 0;
		HRESULT ret = d3d11->CreateTexture1D(&desc, &initialData, &Devices[d3d11]->mIniTexture);
		// Since we need to bind the texture to a shader input, we also need a resource view.
		// The pDesc is set to NULL so that it will simply use the desc format above.
		D3D11_SHADER_RESOURCE_VIEW_DESC descRV;
		memset(&descRV, 0, sizeof(D3D11_SHADER_RESOURCE_VIEW_DESC));
		ret = d3d11->CreateShaderResourceView(Devices[d3d11]->mIniTexture, NULL, &Devices[d3d11]->mIniResourceView);
	}
}

typedef HRESULT(STDMETHODCALLTYPE* DXGI_Present)(IDXGISwapChain* This, UINT SyncInterval, UINT Flags);
static struct {
	SIZE_T nHookId;
	DXGI_Present fnDXGI_Present;
} sDXGI_Present_Hook = { 12, NULL };
HRESULT STDMETHODCALLTYPE DXGIH_Present(IDXGISwapChain* This, UINT SyncInterval, UINT Flags) {
	LogInfo("Present\n");
	frameFunction();
	if (gDevice != 0)
		gDevice->mParamTextureManager->UpdateStereoTexture(gDevice->mDevice, gContext, gDevice->mStereoTexture, false);
	return sDXGI_Present_Hook.fnDXGI_Present(This, SyncInterval, Flags);
}

void hook(ID3D11Device** ppDevice, nv::stereo::ParamTextureManagerD3D11 *gStereoTexMgr) {
	if (ppDevice != NULL && *ppDevice != NULL) {
		LogInfo("Hook device: %p\n", *ppDevice);
		if (!gl_hookedDevice) {
			DWORD_PTR*** vTable = (DWORD_PTR***)*ppDevice;
			//D3D11_CT2D origCT2D = (D3D11_CT2D)(*vTable)[5];

			D3D11_VS origVS = (D3D11_VS)(*vTable)[12];
			D3D11_GS origGS = (D3D11_GS)(*vTable)[13];
			D3D11_PS origPS = (D3D11_PS)(*vTable)[15];
			D3D11_HS origHS = (D3D11_HS)(*vTable)[16];
			D3D11_DS origDS = (D3D11_DS)(*vTable)[17];
			D3D11_CS origCS = (D3D11_CS)(*vTable)[18];

			D3D11_GIC origGIC = (D3D11_GIC)(*vTable)[40];

			//cHookMgr.Hook(&(sCreateTexture2D_Hook.nHookId), (LPVOID*)&(sCreateTexture2D_Hook.fnCreateTexture2D), origCT2D, D3D11_CreateTexture2D);

			cHookMgr.Hook(&(sCreatePixelShader_Hook.nHookId), (LPVOID*)&(sCreatePixelShader_Hook.fnCreatePixelShader), origPS, D3D11_CreatePixelShader);
			cHookMgr.Hook(&(sCreateVertexShader_Hook.nHookId), (LPVOID*)&(sCreateVertexShader_Hook.fnCreateVertexShader), origVS, D3D11_CreateVertexShader);
			cHookMgr.Hook(&(sCreateComputeShader_Hook.nHookId), (LPVOID*)&(sCreateComputeShader_Hook.fnCreateComputeShader), origCS, D3D11_CreateComputeShader);
			cHookMgr.Hook(&(sCreateGeometryShader_Hook.nHookId), (LPVOID*)&(sCreateGeometryShader_Hook.fnCreateGeometryShader), origGS, D3D11_CreateGeometryShader);
			cHookMgr.Hook(&(sCreateDomainShader_Hook.nHookId), (LPVOID*)&(sCreateDomainShader_Hook.fnCreateDomainShader), origDS, D3D11_CreateDomainShader);
			cHookMgr.Hook(&(sCreateHullShader_Hook.nHookId), (LPVOID*)&(sCreateHullShader_Hook.fnCreateHullShader), origHS, D3D11_CreateHullShader);

			cHookMgr.Hook(&(sGetImmediateContext_Hook.nHookId), (LPVOID*)&(sGetImmediateContext_Hook.fnGetImmediateContext), origGIC, D3D11_GetImmediateContext);



			IDXGIFactory1 * pFactory;
			HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)(&pFactory));

			// Temp window
			HWND dummyHWND = ::CreateWindow("STATIC", "dummy", WS_DISABLED, 0, 0, 1, 1, NULL, NULL, NULL, NULL);
			::SetWindowTextA(dummyHWND, "Dummy Window!");

			// create a struct to hold information about the swap chain
			DXGI_SWAP_CHAIN_DESC scd;

			// clear out the struct for use
			ZeroMemory(&scd, sizeof(DXGI_SWAP_CHAIN_DESC));

			// fill the swap chain description struct
			scd.BufferCount = 1;									// one back buffer
			scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;		// use 32-bit color
			scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;		// how swap chain is to be used
			scd.OutputWindow = dummyHWND;							// the window to be used
			scd.SampleDesc.Count = 1;								// how many multisamples
			scd.Windowed = TRUE;									// windowed/full-screen mode

			IDXGISwapChain * pSC;

			pFactory->CreateSwapChain(*ppDevice, &scd, &pSC);

			DWORD_PTR*** vTable2 = (DWORD_PTR***)pSC;
			DXGI_Present origPresent = (DXGI_Present)(*vTable2)[8];

			pSC->Release();
			pFactory->Release();
			::DestroyWindow(dummyHWND);

			cHookMgr.Hook(&(sDXGI_Present_Hook.nHookId), (LPVOID*)&(sDXGI_Present_Hook.fnDXGI_Present), origPresent, DXGIH_Present);

			gl_hookedDevice = true;
		}

		auto gDevice = *ppDevice;
		auto device = new DeviceClass(gDevice, gStereoTexMgr);
		Devices[gDevice] = device;
		if (NVAPI_OK != NvAPI_Stereo_CreateHandleFromIUnknown(*ppDevice, &device->mStereoHandle))
			device->mStereoHandle = 0;

		CreateINITexture(gDevice);
		// Create our stereo parameter texture
		CreateStereoParamTextureAndView(gDevice);
		// Initialize the stereo texture manager. Note that the StereoTextureManager was created
		// before the device. This is important, because NvAPI_Stereo_CreateConfigurationProfileRegistryKey
		// must be called BEFORE device creation.
		gStereoTexMgr->Init(gDevice);
	} else {
		delete gStereoTexMgr;
	}
}

void ShowStartupScreen()
{
	BOOL affinity = -1;
	DWORD_PTR one = 0x01;
	DWORD_PTR before = 0;
	DWORD_PTR before2 = 0;
	affinity = GetProcessAffinityMask(GetCurrentProcess(), &before, &before2);
	affinity = SetProcessAffinityMask(GetCurrentProcess(), one);
	HBITMAP hBM = ::LoadBitmap(gl_hThisInstance, MAKEINTRESOURCE(IDB_STARTUP));
	if (hBM) {
		HDC hDC = ::GetDC(NULL);
		if (hDC) {
			int iXPos = (::GetDeviceCaps(hDC, HORZRES) / 2) - (128 / 2);
			int iYPos = (::GetDeviceCaps(hDC, VERTRES) / 2) - (128 / 2);

			// paint the "GPP active" sign on desktop
			HDC hMemDC = ::CreateCompatibleDC(hDC);
			HBITMAP hBMold = (HBITMAP) ::SelectObject(hMemDC, hBM);
			::BitBlt(hDC, iXPos, iYPos, 128, 128, hMemDC, 0, 0, SRCCOPY);

			//Cleanup
			::SelectObject(hMemDC, hBMold);
			::DeleteDC(hMemDC);
			::ReleaseDC(NULL, hDC);

			// Wait 1 seconds before proceeding
			::Sleep(2000);
		}
		::DeleteObject(hBM);
	}
	affinity = SetProcessAffinityMask(GetCurrentProcess(), before);
}

// Exported function (faking d3d11.dll's export)
HRESULT WINAPI D3D11CreateDevice(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags, const D3D_FEATURE_LEVEL *pFeatureLevels, 
									UINT FeatureLevels, UINT SDKVersion, ID3D11Device **ppDevice, D3D_FEATURE_LEVEL *pFeatureLevel, ID3D11DeviceContext **ppImmediateContext) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d11.dll"
	
	// Hooking IDirect3D Object from Original Library
	typedef HRESULT (WINAPI* D3D11_Type)(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags, const D3D_FEATURE_LEVEL *pFeatureLevels,
											UINT FeatureLevels, UINT SDKVersion, ID3D11Device **ppDevice, D3D_FEATURE_LEVEL *pFeatureLevel, ID3D11DeviceContext **ppImmediateContext);
	D3D11_Type D3D11CreateDevice_fn = (D3D11_Type) GetProcAddress( gl_hOriginalDll, "D3D11CreateDevice");
	// ParamTextureManager must be created before the device to give our settings-loading code a chance to fire.
	auto gStereoTexMgr = new nv::stereo::ParamTextureManagerD3D11;
	HRESULT res = D3D11CreateDevice_fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
	if (!FAILED(res)) {
		hook(ppDevice, gStereoTexMgr);
	} else {
		delete gStereoTexMgr;
	}
	return res;
}
HRESULT WINAPI D3D11CreateDeviceAndSwapChain(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, UINT Flags, const D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
							const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc, IDXGISwapChain **ppSwapChain, ID3D11Device **ppDevice, D3D_FEATURE_LEVEL *pFeatureLevel, ID3D11DeviceContext **ppImmediateContext) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d11.dll"

	// Hooking IDirect3D Object from Original Library
	typedef HRESULT(WINAPI* D3D11_Type)(IDXGIAdapter *pAdapter, D3D_DRIVER_TYPE DriverType, HMODULE Software, INT Flags, const D3D_FEATURE_LEVEL *pFeatureLevels, UINT FeatureLevels, UINT SDKVersion,
							const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc, IDXGISwapChain **ppSwapChain, ID3D11Device **ppDevice, D3D_FEATURE_LEVEL *pFeatureLevel, ID3D11DeviceContext **ppImmediateContext);
	D3D11_Type D3D11CreateDeviceAndSwapChain_fn = (D3D11_Type)GetProcAddress(gl_hOriginalDll, "D3D11CreateDeviceAndSwapChain");
	// ParamTextureManager must be created before the device to give our settings-loading code a chance to fire.
	auto gStereoTexMgr = new nv::stereo::ParamTextureManagerD3D11;
	HRESULT res = D3D11CreateDeviceAndSwapChain_fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
	if (!FAILED(res)) {
		hook(ppDevice, gStereoTexMgr);
	} else {
		delete gStereoTexMgr;
	}
	return res;
}
#pragma endregion

void InitShaders() {
	skip.clear();

	char INIfile[MAX_PATH];

	_getcwd(INIfile, MAX_PATH);
	strcat_s(INIfile, MAX_PATH, "\\d3dx.ini");

	vector<string> Shaders;
	char sectionNames[10000];
	GetPrivateProfileSectionNames(sectionNames, 10000, INIfile);
	int position = 0;
	int length = strlen(&sectionNames[position]);
	while (length != 0) {
		if (strncmp(&sectionNames[position], "ShaderOverride", 14) == 0)
			Shaders.push_back(&sectionNames[position]);
		position += length + 1;
		length = strlen(&sectionNames[position]);
	}

	char buf[MAX_PATH];

	for (size_t i = 0; i < Shaders.size(); i++) {
		const char* id = Shaders[i].c_str();
		UINT64 hash;
		if (GetPrivateProfileString(id, "Hash", 0, buf, MAX_PATH, INIfile))
			sscanf_s(buf, "%16llx", &hash);
		skip.insert(hash);
	}
}

void InitInstance() 
{
	// Initialisation
	char setting[MAX_PATH];
	char INIfile[MAX_PATH];
	char LOGfile[MAX_PATH];
	int read;

	InitializeCriticalSection(&gl_CS);

	_getcwd(INIfile, MAX_PATH);
	_getcwd(LOGfile, MAX_PATH);
	strcat_s(INIfile, MAX_PATH, "\\d3dx.ini");
	_getcwd(cwd, MAX_PATH);

	// If specified in Debug section, wait for Attach to Debugger.
	bool waitfordebugger = GetPrivateProfileInt("Debug", "attach", 0, INIfile) > 0;
	if (waitfordebugger) {
		do {
			Sleep(250);
		} while (!IsDebuggerPresent());
	}

	gl_dumpBin = GetPrivateProfileInt("Rendering", "export_binary", gl_dumpBin, INIfile) > 0;
	gl_log = GetPrivateProfileInt("Logging", "calls", gl_log, INIfile) > 0;
	gl_hunt = GetPrivateProfileInt("Hunting", "hunting", gl_hunt, INIfile) > 0;
	gl_cache_shaders = GetPrivateProfileInt("Rendering", "cache_shaders", gl_cache_shaders, INIfile) > 0;
	
	GetPrivateProfileString("Hunting", "next_pixelshader", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "next_pixelshader"));
	GetPrivateProfileString("Hunting", "previous_pixelshader", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "previous_pixelshader"));
	GetPrivateProfileString("Hunting", "mark_pixelshader", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "mark_pixelshader"));

	GetPrivateProfileString("Hunting", "next_vertexshader", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "next_vertexshader"));
	GetPrivateProfileString("Hunting", "previous_vertexshader", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "previous_vertexshader"));
	GetPrivateProfileString("Hunting", "mark_vertexshader", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "mark_vertexshader"));

	GetPrivateProfileString("Hunting", "reload_fixes", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "reload_fixes"));

	GetPrivateProfileString("Hunting", "toggle_hunting", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "toggle_hunting"));

	GetPrivateProfileString("Hunting", "show_original", 0, setting, MAX_PATH, INIfile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "show_original"));

	// Read in any constants defined in the ini, for use as shader parameters
	read = GetPrivateProfileString("Constants", "x", 0, setting, MAX_PATH, INIfile);
	if (read) iniParams.x = stof(setting);
	read = GetPrivateProfileString("Constants", "y", 0, setting, MAX_PATH, INIfile);
	if (read) iniParams.y = stof(setting);
	read = GetPrivateProfileString("Constants", "z", 0, setting, MAX_PATH, INIfile);
	if (read) iniParams.z = stof(setting);
	read = GetPrivateProfileString("Constants", "w", 0, setting, MAX_PATH, INIfile);
	if (read) iniParams.w = stof(setting);

	if (gl_log) {
		if (LogFile == NULL) {
			strcat_s(LOGfile, MAX_PATH, "\\d3d11_log.txt");
			LogFile = _fsopen(LOGfile, "w", _SH_DENYNO);
			setvbuf(LogFile, NULL, _IONBF, 0);
		}
	}

	InitShaders();

	KeyType type;
	char key[MAX_PATH];
	char buf[MAX_PATH];

	vector<string> Keys;
	vector<string> Textures;
	char sectionNames[10000];
	GetPrivateProfileSectionNames(sectionNames, 10000, INIfile);
	int position = 0;
	int length = strlen(&sectionNames[position]);
	while (length != 0) {
		if (strncmp(&sectionNames[position], "Key", 3) == 0)
			Keys.push_back(&sectionNames[position]);
		if (strncmp(&sectionNames[position], "TextureOverride", 15) == 0)
			Textures.push_back(&sectionNames[position]);
		position += length + 1;
		length = strlen(&sectionNames[position]);
	}

	for (size_t i = 0; i < Textures.size(); i++) {
		const char* id = Textures[i].c_str();
		UINT64 hash;
		if (GetPrivateProfileString(id, "Hash", 0, buf, MAX_PATH, INIfile))
			sscanf_s(buf, "%16llx", &hash);
	}

	for (size_t i = 0; i < Keys.size(); i++) {
		const char* id = Keys[i].c_str();
		if (!GetPrivateProfileString(id, "Key", 0, key, MAX_PATH, INIfile))
			continue;

		type = KeyType::Activate;

		if (GetPrivateProfileString(id, "type", 0, buf, MAX_PATH, INIfile)) {
			if (!_stricmp(buf, "hold")) {
				type = KeyType::Hold;
			} else if (!_stricmp(buf, "toggle")) {
				type = KeyType::Toggle;
			} else if (!_stricmp(buf, "cycle")) {
				type = KeyType::Cycle;
			}
		}

		TransitionType tType = TransitionType::Linear;
		if (GetPrivateProfileString(id, "transition_type", 0, buf, MAX_PATH, INIfile)) {
			if (!_stricmp(buf, "cosine"))
				tType = TransitionType::Cosine;
		}

		TransitionType rtType = TransitionType::Linear;
		if (GetPrivateProfileString(id, "release_transition_type", 0, buf, MAX_PATH, INIfile)) {
			if (!_stricmp(buf, "cosine"))
				rtType = TransitionType::Cosine;
		}

		vector<string> fs = { "", "", "", "", "", "", "", "", "", "" };
		int varFlags = 0;

		if (GetPrivateProfileString(id, "x", 0, buf, MAX_PATH, INIfile)) {
			fs[0] = buf;
			varFlags |= 1;
		}
		if (GetPrivateProfileString(id, "y", 0, buf, MAX_PATH, INIfile)) {
			fs[1] = buf;
			varFlags |= 2;
		}
		if (GetPrivateProfileString(id, "z", 0, buf, MAX_PATH, INIfile)) {
			fs[2] = buf;
			varFlags |= 4;
		}
		if (GetPrivateProfileString(id, "w", 0, buf, MAX_PATH, INIfile)) {
			fs[3] = buf;
			varFlags |= 8;
		}
		if (GetPrivateProfileString(id, "convergence", 0, buf, MAX_PATH, INIfile)) {
			fs[4] = buf;
			varFlags |= 16;
		}
		if (GetPrivateProfileString(id, "separation", 0, buf, MAX_PATH, INIfile)) {
			fs[5] = buf;
			varFlags |= 32;
		}
		if (GetPrivateProfileString(id, "delay", 0, buf, MAX_PATH, INIfile)) {
			fs[6] = buf;
			varFlags |= 64;
		}
		if (GetPrivateProfileString(id, "transition", 0, buf, MAX_PATH, INIfile)) {
			fs[7] = buf;
			varFlags |= 128;
		}
		if (GetPrivateProfileString(id, "release_delay", 0, buf, MAX_PATH, INIfile)) {
			fs[8] = buf;
			varFlags |= 256;
		}
		if (GetPrivateProfileString(id, "release_transition", 0, buf, MAX_PATH, INIfile)) {
			fs[9] = buf;
			varFlags |= 512;
		}
		BHs.push_back(new ButtonHandler(createButton(key), type, varFlags, fs, tType, rtType));
	}

	WIN32_FIND_DATA findFileData;

	HANDLE hFind = FindFirstFile("ShaderFixes\\????????????????-??.bin", &findFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			string s = findFileData.cFileName;
			string sHash = s.substr(0, 16);
			UINT64 _crc = stoull(sHash, NULL, 16);
			isCache[_crc] = true;
		} while (FindNextFile(hFind, &findFileData));
		FindClose(hFind);
	}

	hFind = FindFirstFile("ShaderFixes\\????????????????-??.txt", &findFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			string s = findFileData.cFileName;
			string sHash = s.substr(0, 16);
			UINT64 _crc = stoull(sHash, NULL, 16);
			hasStartPatch[_crc] = true;
		} while (FindNextFile(hFind, &findFileData));
		FindClose(hFind);
	}

	hFind = FindFirstFile("ShaderFixes\\????????????????-??_replace.txt", &findFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			string s = findFileData.cFileName;
			string sHash = s.substr(0, 16);
			UINT64 _crc = stoull(sHash, NULL, 16);
			hasStartFix[_crc] = true;
		} while (FindNextFile(hFind, &findFileData));
		FindClose(hFind);
	}
	LogInfo("ini loaded:\n");
}

void LoadOriginalDll(void)
{
	wchar_t sysDir[MAX_PATH];
	::GetSystemDirectoryW(sysDir, MAX_PATH);
	wcscat_s(sysDir, MAX_PATH, L"\\d3d11_org.dll");
	if (!gl_hOriginalDll) gl_hOriginalDll = ::LoadLibraryExW(sysDir, NULL, NULL);
}

void ExitInstance() 
{    
	if (gl_hOriginalDll)
	{
		::FreeLibrary(gl_hOriginalDll);
	    gl_hOriginalDll = NULL;  
	}
}