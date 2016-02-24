// proxydll.cpp
#include "proxy11dll.h"
#define NO_STEREO_D3D9
#define NO_STEREO_D3D10
#include "nvstereo.h"
#include "Nektra\NktHookLib.h"
#include "log.h"
#include <map>
#include <DirectXMath.h>
#include <D3Dcompiler.h>
#include "vkeys.h"
#include <algorithm>
#include <Xinput.h>
#include "resource.h"
#define _USE_MATH_DEFINES
#include <math.h>

// global variables
#pragma data_seg (".d3d11_shared")
HINSTANCE           gl_hOriginalDll;
HINSTANCE           gl_hThisInstance;
bool				gl_hookedDevice = false;
bool				gl_hookedContext = false;
bool				gl_Present_hooked = false;
bool				gl_dump = false;
bool				gl_log = false;
bool				gl_cache_shaders = false;
bool				gl_hunt = false;
bool				gl_nvapi = false;
char				cwd[MAX_PATH];
FILE *LogFile = 0;		// off by default.
bool gLogDebug = false;
CRITICAL_SECTION	gl_CS;
DirectX::XMFLOAT4	iniParams[INI_PARAMS_SIZE];
nv::stereo::ParamTextureManagerD3D11 *gStereoTexMgr = NULL;
ID3D11DeviceContext * gContext = NULL;
ID3D11Device *gDevice = NULL;
StereoHandle gStereoHandle = NULL;
ID3D11Texture2D *gStereoTexture = NULL;
ID3D11ShaderResourceView *gStereoResourceView = NULL;
ID3D11Texture1D *gIniTexture = NULL;
ID3D11ShaderResourceView *gIniResourceView = NULL;
ResolutionInfo gResolutionInfo;

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

ID3D11VertexShader * currentVS;
ID3D11PixelShader * currentPS;
ID3D11ComputeShader * currentCS;
ID3D11GeometryShader * currentGS;
ID3D11DomainShader * currentDS;
ID3D11HullShader * currentHS;

map<UINT64, UINT64> crc2;

map<UINT64, ID3D11PixelShader*> PresentPS;
map<UINT64, ID3D11VertexShader*> PresentVS;
UINT64 PS_hash = -1;
UINT64 VS_hash = -1;

ShaderOverrideMap mShaderOverrideMap;
TextureOverrideMap mTextureOverrideMap;

std::unordered_map<ID3D11Texture2D *, UINT64> mTexture2D_ID;
std::unordered_map<ID3D11Texture3D *, UINT64> mTexture3D_ID;

int gSurfaceSquareCreateMode = -1;

// Used for deny_cpu_read texture override
typedef std::unordered_map<ID3D11Resource *, void *> DeniedMap;
DeniedMap mDeniedMaps;
#pragma data_seg ()
// The Log file and the Globals are both used globally, and these are the actual
// definitions of the variables.  All other uses will be via the extern in the 
// globals.h and log.h files.



CNktHookLib cHookMgr;

#pragma region hook
typedef HMODULE(WINAPI *lpfnLoadLibraryExW)(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags);
static HMODULE WINAPI Hooked_LoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags);
static struct
{
	SIZE_T nHookId;
	lpfnLoadLibraryExW fnLoadLibraryExW;
} sLoadLibraryExW_Hook = { 0, NULL };

// ----------------------------------------------------------------------------

static HMODULE ReplaceOnMatch(LPCWSTR lpLibFileName, HANDLE hFile,
	DWORD dwFlags, LPCWSTR our_name, LPCWSTR library)
{
	WCHAR fullPath[MAX_PATH];

	// We can use System32 for all cases, because it will be properly rerouted
	// to SysWow64 by LoadLibraryEx itself.

	if (GetSystemDirectoryW(fullPath, ARRAYSIZE(fullPath)) == 0)
		return NULL;
	wcscat_s(fullPath, MAX_PATH, L"\\");
	wcscat_s(fullPath, MAX_PATH, library);

	// Bypass the known expected call from our wrapped d3d11 & nvapi, where it needs
	// to call to the system to get APIs. This is a bit of a hack, but if the string
	// comes in as original_d3d11/nvapi/nvapi64, that's from us, and needs to switch 
	// to the real one. The test string should have no path attached.

	if (_wcsicmp(lpLibFileName, our_name) == 0)
	{
		//LogInfoW(L"Hooked_LoadLibraryExW switching to original dll: %s to %s.\n",
			//lpLibFileName, fullPath);

		return sLoadLibraryExW_Hook.fnLoadLibraryExW(fullPath, hFile, dwFlags);
	}

	// For this case, we want to see if it's the game loading d3d11 or nvapi directly
	// from the system directory, and redirect it to the game folder if so, by stripping
	// the system path. This is to be case insensitive as we don't know if NVidia will 
	// change that and otherwise break it it with a driver upgrade. 

	if (_wcsicmp(lpLibFileName, fullPath) == 0)
	{
		//LogInfoW(L"Replaced Hooked_LoadLibraryExW for: %s to %s.\n", lpLibFileName, library);

		return sLoadLibraryExW_Hook.fnLoadLibraryExW(library, hFile, dwFlags);
	}

	return NULL;
}

// Function called for every LoadLibraryExW call once we have hooked it.
// We want to look for overrides to System32 that we can circumvent.  This only happens
// in the current process, not system wide.
// 
// We need to do two things here.  First, we need to bypass all calls that go
// directly to the System32 folder, because that will circumvent our wrapping 
// of the d3d11 and nvapi APIs. The nvapi itself does this specifically as fake
// security to avoid proxy DLLs like us. 
// Second, because we are now forcing all LoadLibraryExW calls back to the game
// folder, we need somehow to allow us access to the original dlls so that we can
// get the original proc addresses to call.  We do this with the original_* names
// passed in to this routine.
//
// There three use cases:
// x32 game on x32 OS
//	 LoadLibraryExW("C:\Windows\system32\d3d11.dll", NULL, 0)
//	 LoadLibraryExW("C:\Windows\system32\nvapi.dll", NULL, 0)
// x64 game on x64 OS
//	 LoadLibraryExW("C:\Windows\system32\d3d11.dll", NULL, 0)
//	 LoadLibraryExW("C:\Windows\system32\nvapi64.dll", NULL, 0)
// x32 game on x64 OS
//	 LoadLibraryExW("C:\Windows\SysWOW64\d3d11.dll", NULL, 0)
//	 LoadLibraryExW("C:\Windows\SysWOW64\nvapi.dll", NULL, 0)
//
// To be general and simplify the init, we are going to specifically do the bypass 
// for all variants, even though we only know of this happening on x64 games.  
//
// An important thing to remember here is that System32 is automatically rerouted
// to SysWow64 by the OS as necessary, so we can use System32 in all cases.
//
// It's not clear if we should also hook LoadLibraryW, but we don't have examples
// where we need that yet.

static HMODULE WINAPI Hooked_LoadLibraryExW(_In_ LPCWSTR lpLibFileName, _Reserved_ HANDLE hFile, _In_ DWORD dwFlags)
{
	HMODULE module;

	module = ReplaceOnMatch(lpLibFileName, hFile, dwFlags, L"original_d3d11.dll", L"d3d11.dll");
	if (module)
		return module;

	module = ReplaceOnMatch(lpLibFileName, hFile, dwFlags, L"original_nvapi64.dll", L"nvapi64.dll");
	if (module) {
		gl_nvapi = true;
		return module;
	}

	module = ReplaceOnMatch(lpLibFileName, hFile, dwFlags, L"original_nvapi.dll", L"nvapi.dll");
	if (module) {
		gl_nvapi = true;
		return module;
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
	if (hKernel32 == NULL)
		return false;

	// Only ExW version for now, used by nvapi.
	fnOrigLoadLibrary = NktHookLibHelpers::GetProcedureAddress(hKernel32, "LoadLibraryExW");
	if (fnOrigLoadLibrary == NULL)
		return false;

	dwOsErr = cHookMgr.Hook(&(sLoadLibraryExW_Hook.nHookId), (LPVOID*)&(sLoadLibraryExW_Hook.fnLoadLibraryExW),
		fnOrigLoadLibrary, Hooked_LoadLibraryExW);

	return (dwOsErr == 0) ? true : false;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
	bool result = true;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		gl_hThisInstance = hinstDLL;
		ShowStartupScreen();
		result = InstallHooks();
		InitInstance();
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
#pragma endregion

// Primary hash calculation for all shader file names, all textures.
// 64 bit magic FNV-0 and FNV-1 prime
#define FNV_64_PRIME ((UINT64)0x100000001b3ULL)
static UINT64 fnv_64_buf(const void *buf, size_t len)
{
	UINT64 hval = 0;
	unsigned const char *bp = (unsigned const char *)buf;	/* start of buffer */
	unsigned const char *be = bp + len;		/* beyond end of buffer */

											// FNV-1 hash each octet of the buffer
	while (bp < be)
	{
		// multiply by the 64 bit FNV magic prime mod 2^64 */
		hval *= FNV_64_PRIME;
		// xor the bottom with the current octet
		hval ^= (UINT64)*bp++;
	}
	return hval;
}

#pragma region Create
void dump(const void* pShaderBytecode, SIZE_T BytecodeLength, char* buffer) {
	char path[MAX_PATH];
	path[0] = 0;
	strcat_s(path, MAX_PATH, cwd);
	strcat_s(path, MAX_PATH, "\\ShaderCache");
	CreateDirectory(path, NULL);
	strcat_s(path, MAX_PATH, "\\");
	strcat_s(path, MAX_PATH, buffer);
	strcat_s(path, MAX_PATH, ".bin");
	EnterCriticalSection(&gl_CS);
	FILE* f;
	fopen_s(&f, path, "wb");
	fwrite(pShaderBytecode, 1, BytecodeLength, f);
	fclose(f);
	LeaveCriticalSection(&gl_CS);
}
vector<byte> cached(char* buffer, UINT64* _crc2) {
	char path[MAX_PATH];
	path[0] = 0;
	strcat_s(path, MAX_PATH, cwd);
	strcat_s(path, MAX_PATH, "\\ShaderFixes\\");
	strcat_s(path, MAX_PATH, buffer);
	strcat_s(path, MAX_PATH, ".bin");
	auto file = readFile(path);
	*_crc2 = fnv_64_buf(file.data(), file.size());
	return file;
}
vector<byte> assembled(char* buffer, vector<byte> *v, UINT64* _crc2) {
	char path[MAX_PATH];
	path[0] = 0;
	strcat_s(path, MAX_PATH, cwd);
	strcat_s(path, MAX_PATH, "\\ShaderFixes\\");
	strcat_s(path, MAX_PATH, buffer);
	strcat_s(path, MAX_PATH, ".txt");
	auto file = readFile(path);

	vector<byte> byteCode = assembler(file, *v);
	*_crc2 = fnv_64_buf(byteCode.data(), byteCode.size());
	if (gl_cache_shaders) {
		FILE* f;
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderFixes\\");
		strcat_s(path, MAX_PATH, buffer);
		strcat_s(path, MAX_PATH, ".bin");

		EnterCriticalSection(&gl_CS);
		fopen_s(&f, path, "wb");
		fwrite(byteCode.data(), 1, byteCode.size(), f);
		fclose(f);
		LeaveCriticalSection(&gl_CS);
	}
	return byteCode;
}
ID3DBlob* hlsled(char* buffer, char* shdModel, UINT64* _crc2){
	char path[MAX_PATH];
	path[0] = 0;
	strcat_s(path, MAX_PATH, cwd);
	strcat_s(path, MAX_PATH, "\\ShaderFixes\\");
	strcat_s(path, MAX_PATH, buffer);
	strcat_s(path, MAX_PATH, "_replace.txt");
	auto file = readFile(path);

	ID3DBlob* pByteCode = nullptr;
	ID3DBlob* pErrorMsgs = nullptr;
	HRESULT ret = D3DCompile(file.data(), file.size(), NULL, 0, ((ID3DInclude*)(UINT_PTR)1),
		"main", shdModel, D3DCOMPILE_OPTIMIZATION_LEVEL3, 0, &pByteCode, &pErrorMsgs);
	if (SUCCEEDED(ret)) {
		*_crc2 = fnv_64_buf(pByteCode->GetBufferPointer(), pByteCode->GetBufferSize());
		if (gl_cache_shaders) {
			path[0] = 0;
			strcat_s(path, MAX_PATH, cwd);
			strcat_s(path, MAX_PATH, "\\ShaderFixes\\");
			strcat_s(path, MAX_PATH, buffer);
			strcat_s(path, MAX_PATH, ".bin");

			EnterCriticalSection(&gl_CS);
			FILE* f;
			fopen_s(&f, path, "wb");
			fwrite(pByteCode->GetBufferPointer(), 1, pByteCode->GetBufferSize(), f);
			fclose(f);
			LeaveCriticalSection(&gl_CS);
		}
	}
	return pByteCode;
}

HRESULT STDMETHODCALLTYPE D3D11_CreateVertexShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11VertexShader **ppVertexShader) {
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	LogInfo("Create VertexShader: %016llX\n", _crc);
	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	char buffer[80];
	sprintf_s(buffer, 80, "%016llX-vs", _crc);
	if (gl_dump)
		dump(pShaderBytecode, BytecodeLength, buffer);
	ID3D11VertexShader * shader;
	HRESULT res = sCreateVertexShader_Hook.fnCreateVertexShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppVertexShader);
	if (isCache.count(_crc)) {
		auto file = cached(buffer, &_crc2);
		res = sCreateVertexShader_Hook.fnCreateVertexShader(This, file.data(), file.size(), pClassLinkage, &shader);
	} else if (hasStartPatch.count(_crc)) {
		auto data = assembled(buffer, v, &_crc2);
		res = sCreateVertexShader_Hook.fnCreateVertexShader(This, data.data(), data.size(), pClassLinkage, &shader);
	} else if (hasStartFix.count(_crc)) {
		ID3DBlob* pByteCode = hlsled(buffer, "vs_5_0", &_crc2);
		if (_crc2)
			res = sCreateVertexShader_Hook.fnCreateVertexShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &shader);
	}
	shaderMapVS[*ppVertexShader] = _crc;
	VSmap[*ppVertexShader] = *ppVertexShader;
	if (_crc2 && _crc != _crc2) {
		crc2[_crc] = _crc2;
		VSmap[*ppVertexShader] = shader;
	}
	return res;
}

HRESULT STDMETHODCALLTYPE D3D11_CreatePixelShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11PixelShader **ppPixelShader) {
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	LogInfo("Create PixelShader: %016llX\n", _crc);
	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	char buffer[80];
	sprintf_s(buffer, 80, "%016llX-ps", _crc);
	if (gl_dump)
		dump(pShaderBytecode, BytecodeLength, buffer);
	ID3D11PixelShader * shader;
	HRESULT res = sCreatePixelShader_Hook.fnCreatePixelShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader);
	if (isCache.count(_crc)) {
		auto file = cached(buffer, &_crc2);
		res = sCreatePixelShader_Hook.fnCreatePixelShader(This, file.data(), file.size(), pClassLinkage, &shader);
	} else if (hasStartPatch.count(_crc)) {
		auto data = assembled(buffer, v, &_crc2);
		res = sCreatePixelShader_Hook.fnCreatePixelShader(This, data.data(), data.size(), pClassLinkage, &shader);
	} else if (hasStartFix.count(_crc)) {
		ID3DBlob* pByteCode = hlsled(buffer, "ps_5_0", &_crc2);
		if (_crc2)
			res = sCreatePixelShader_Hook.fnCreatePixelShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &shader);
	}
	shaderMapPS[*ppPixelShader] = _crc;
	PSmap[*ppPixelShader] = *ppPixelShader;
	if (_crc2 && _crc != _crc2) {
		crc2[_crc] = _crc2;
		PSmap[*ppPixelShader] = shader;
	}
	return res;
}

HRESULT STDMETHODCALLTYPE D3D11_CreateGeometryShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11GeometryShader **ppGeometryShader) {
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	LogInfo("Create GeometryShader: %016llX\n", _crc);
	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	char buffer[80];
	sprintf_s(buffer, 80, "%016llX-gs", _crc);
	if (gl_dump)
		dump(pShaderBytecode, BytecodeLength, buffer);
	ID3D11GeometryShader * shader;
	HRESULT res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppGeometryShader);
	if (isCache.count(_crc)) {
		auto file = cached(buffer, &_crc2);
		res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, file.data(), file.size(), pClassLinkage, &shader);
	} else if (hasStartPatch.count(_crc)) {
		auto data = assembled(buffer, v, &_crc2);
		res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, data.data(), data.size(), pClassLinkage, &shader);
	} else if (hasStartFix.count(_crc)) {
		ID3DBlob* pByteCode = hlsled(buffer, "gs_5_0", &_crc2);
		if (_crc2)
			res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &shader);
	}
	shaderMapGS[*ppGeometryShader] = _crc;
	GSmap[*ppGeometryShader] = *ppGeometryShader;
	if (_crc2 && _crc != _crc2) {
		crc2[_crc] = _crc2;
		GSmap[*ppGeometryShader] = shader;
	}
	return res;
}

HRESULT STDMETHODCALLTYPE D3D11_CreateHullShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11HullShader **ppHullShader) {
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	LogInfo("Create HullShader: %016llX\n", _crc);
	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	char buffer[80];
	sprintf_s(buffer, 80, "%016llX-hs", _crc);
	if (gl_dump)
		dump(pShaderBytecode, BytecodeLength, buffer);
	ID3D11HullShader * shader;
	HRESULT res = sCreateHullShader_Hook.fnCreateHullShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppHullShader);
	if (isCache.count(_crc)) {
		auto file = cached(buffer, &_crc2);
		res = sCreateHullShader_Hook.fnCreateHullShader(This, file.data(), file.size(), pClassLinkage, &shader);
	} else if (hasStartPatch.count(_crc)) {
		auto data = assembled(buffer, v, &_crc2);
		res = sCreateHullShader_Hook.fnCreateHullShader(This, data.data(), data.size(), pClassLinkage, &shader);
	} else if (hasStartFix.count(_crc)) {
		ID3DBlob* pByteCode = hlsled(buffer, "hs_5_0", &_crc2);
		if (_crc2)
			res = sCreateHullShader_Hook.fnCreateHullShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &shader);
	}
	shaderMapHS[*ppHullShader] = _crc;
	HSmap[*ppHullShader] = *ppHullShader;
	if (_crc2 && _crc != _crc2) {
		crc2[_crc] = _crc2;
		HSmap[*ppHullShader] = shader;
	}
	return res;
}

HRESULT STDMETHODCALLTYPE D3D11_CreateDomainShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11DomainShader **ppDomainShader) {
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	LogInfo("Create DomainShader: %016llX\n", _crc);
	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	char buffer[80];
	sprintf_s(buffer, 80, "%016llX-ds", _crc);
	if (gl_dump)
		dump(pShaderBytecode, BytecodeLength, buffer);
	ID3D11DomainShader * shader;
	HRESULT res = sCreateDomainShader_Hook.fnCreateDomainShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppDomainShader);
	if (isCache.count(_crc)) {
		auto file = cached(buffer, &_crc2);
		res = sCreateDomainShader_Hook.fnCreateDomainShader(This, file.data(), file.size(), pClassLinkage, &shader);
	} else if (hasStartPatch.count(_crc)) {
		auto data = assembled(buffer, v, &_crc2);
		res = sCreateDomainShader_Hook.fnCreateDomainShader(This, data.data(), data.size(), pClassLinkage, &shader);
	} else if (hasStartFix.count(_crc)) {
		ID3DBlob* pByteCode = hlsled(buffer, "ds_5_0", &_crc2);
		if (_crc2)
			res = sCreateDomainShader_Hook.fnCreateDomainShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &shader);
	}
	shaderMapDS[*ppDomainShader] = _crc;
	DSmap[*ppDomainShader] = *ppDomainShader;
	if (_crc2 && _crc != _crc2) {
		crc2[_crc] = _crc2;
		DSmap[*ppDomainShader] = shader;
	}
	return res;
}

HRESULT STDMETHODCALLTYPE D3D11_CreateComputeShader(ID3D11Device * This, const void *pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage *pClassLinkage, ID3D11ComputeShader **ppComputeShader) {
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	UINT64 _crc2 = 0;
	LogInfo("Create ComputeShader: %016llX\n", _crc);
	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	char buffer[80];
	sprintf_s(buffer, 80, "%016llX-cs", _crc);
	if (gl_dump)
		dump(pShaderBytecode, BytecodeLength, buffer);
	ID3D11ComputeShader * shader;
	HRESULT res = sCreateComputeShader_Hook.fnCreateComputeShader(This, pShaderBytecode, BytecodeLength, pClassLinkage, ppComputeShader);
	if (isCache.count(_crc)) {
		auto file = cached(buffer, &_crc2);
		res = sCreateComputeShader_Hook.fnCreateComputeShader(This, file.data(), file.size(), pClassLinkage, &shader);
	} else if (hasStartPatch.count(_crc)) {
		auto data = assembled(buffer, v, &_crc2);
		res = sCreateComputeShader_Hook.fnCreateComputeShader(This, data.data(), data.size(), pClassLinkage, &shader);
	} else if (hasStartFix.count(_crc)) {
		ID3DBlob* pByteCode = hlsled(buffer, "ds_5_0", &_crc2);
		if (_crc2)
			res = sCreateComputeShader_Hook.fnCreateComputeShader(This, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), pClassLinkage, &shader);
	}
	shaderMapCS[*ppComputeShader] = _crc;
	CSmap[*ppComputeShader] = *ppComputeShader;
	if (_crc2 && _crc != _crc2) {
		crc2[_crc] = _crc2;
		CSmap[*ppComputeShader] = shader;
	}
	return res;
}
#pragma endregion

#pragma region SetShader
map<UINT64, ID3D11PixelShader*> RunningPS;
UINT64 currentPScrc;
void STDMETHODCALLTYPE D3D11C_PSSetShader(ID3D11DeviceContext * This, ID3D11PixelShader *pPixelShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	if (shaderMapPS.count(pPixelShader)) {
		UINT64 _crc = shaderMapPS[pPixelShader];
		LogInfo("PS: %016llX\n", _crc);
		RunningPS[_crc] = pPixelShader;
		currentPScrc = _crc;
	}
	gContext = This;
	sPSSetShader_Hook.fnPSSetShader(This, PSmap[pPixelShader], ppClassInstances, NumClassInstances);
	This->PSSetShaderResources(125, 1, &gStereoResourceView);
	This->PSSetShaderResources(120, 1, &gIniResourceView);
	if (pPixelShader) currentPS = pPixelShader;
}
map<UINT64, ID3D11VertexShader*> RunningVS;
UINT64 currentVScrc;
void STDMETHODCALLTYPE D3D11C_VSSetShader(ID3D11DeviceContext * This, ID3D11VertexShader *pVertexShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	if (shaderMapVS.count(pVertexShader)) {
		UINT64 _crc = shaderMapVS[pVertexShader];
		LogInfo("VS: %016llX\n", _crc);
		RunningVS[_crc] = pVertexShader;
		currentVScrc = _crc;
	}
	gContext = This;
	sVSSetShader_Hook.fnVSSetShader(This, VSmap[pVertexShader], ppClassInstances, NumClassInstances);
	This->VSSetShaderResources(125, 1, &gStereoResourceView);
	This->VSSetShaderResources(120, 1, &gIniResourceView);
	if (pVertexShader) currentVS = pVertexShader;
}
void STDMETHODCALLTYPE D3D11C_CSSetShader(ID3D11DeviceContext * This, ID3D11ComputeShader *pComputeShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	gContext = This;
	sCSSetShader_Hook.fnCSSetShader(This, CSmap[pComputeShader], ppClassInstances, NumClassInstances);
	This->CSSetShaderResources(125, 1, &gStereoResourceView);
	This->CSSetShaderResources(120, 1, &gIniResourceView);
	if (pComputeShader) currentCS = pComputeShader;
}
void STDMETHODCALLTYPE D3D11C_GSSetShader(ID3D11DeviceContext * This, ID3D11GeometryShader *pGeometryShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	gContext = This;
	sGSSetShader_Hook.fnGSSetShader(This, GSmap[pGeometryShader], ppClassInstances, NumClassInstances);
	This->GSSetShaderResources(125, 1, &gStereoResourceView);
	This->GSSetShaderResources(120, 1, &gIniResourceView);
	if (pGeometryShader) currentGS = pGeometryShader;
}
void STDMETHODCALLTYPE D3D11C_HSSetShader(ID3D11DeviceContext * This, ID3D11HullShader *pHullShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	gContext = This;
	sHSSetShader_Hook.fnHSSetShader(This, HSmap[pHullShader], ppClassInstances, NumClassInstances);
	This->HSSetShaderResources(125, 1, &gStereoResourceView);
	This->HSSetShaderResources(120, 1, &gIniResourceView);
	if (pHullShader) currentHS = pHullShader;
}
void STDMETHODCALLTYPE D3D11C_DSSetShader(ID3D11DeviceContext * This, ID3D11DomainShader *pDomainShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances) {
	gContext = This;
	sDSSetShader_Hook.fnDSSetShader(This, DSmap[pDomainShader], ppClassInstances, NumClassInstances);
	This->DSSetShaderResources(125, 1, &gStereoResourceView);
	This->DSSetShaderResources(120, 1, &gIniResourceView);
	if (pDomainShader) currentDS = pDomainShader;
}
#pragma endregion

#pragma region override
ID3D11VertexShader* SwitchVSShader(ID3D11VertexShader *shader)
{

	ID3D11VertexShader *pVertexShader;
	ID3D11ClassInstance *pClassInstances;
	UINT NumClassInstances = 0, i;

	// We can possibly save the need to get the current shader by saving the ClassInstances
	gContext->VSGetShader(&pVertexShader, &pClassInstances, &NumClassInstances);
	gContext->VSSetShader(shader, &pClassInstances, NumClassInstances);

	for (i = 0; i < NumClassInstances; i++)
		pClassInstances[i].Release();

	return pVertexShader;
}

ID3D11PixelShader* SwitchPSShader(ID3D11PixelShader *shader)
{

	ID3D11PixelShader *pPixelShader;
	ID3D11ClassInstance *pClassInstances;
	UINT NumClassInstances = 0, i;

	// We can possibly save the need to get the current shader by saving the ClassInstances
	gContext->PSGetShader(&pPixelShader, &pClassInstances, &NumClassInstances);
	gContext->PSSetShader(shader, &pClassInstances, NumClassInstances);

	for (i = 0; i < NumClassInstances; i++)
		pClassInstances[i].Release();

	return pPixelShader;
}

void ProcessParamRTSize(ParamOverrideCache *cache)
{
	D3D11_RENDER_TARGET_VIEW_DESC view_desc;
	D3D11_TEXTURE2D_DESC res_desc;
	ID3D11RenderTargetView *view = NULL;
	ID3D11Resource *res = NULL;
	ID3D11Texture2D *tex = NULL;

	if (cache->rt_width != -1)
		return;

	gContext->OMGetRenderTargets(1, &view, NULL);
	if (!view)
		return;

	view->GetDesc(&view_desc);

	if (view_desc.ViewDimension != D3D11_RTV_DIMENSION_TEXTURE2D &&
		view_desc.ViewDimension != D3D11_RTV_DIMENSION_TEXTURE2DMS)
		goto out_release_view;

	view->GetResource(&res);
	if (!res)
		goto out_release_view;

	tex = (ID3D11Texture2D *)res;
	tex->GetDesc(&res_desc);

	cache->rt_width = (float)res_desc.Width;
	cache->rt_height = (float)res_desc.Height;

	tex->Release();
out_release_view:
	view->Release();
}

bool ProcessParamOverride(float *dest, ParamOverride *override, ParamOverrideCache *cache)
{
	float orig = *dest;

	switch (override->type) {
	case ParamOverrideType::INVALID:
		return false;
	case ParamOverrideType::VALUE:
		*dest = override->val;
		break;
	case ParamOverrideType::RT_WIDTH:
		ProcessParamRTSize(cache);
		*dest = cache->rt_width;
		break;
	case ParamOverrideType::RT_HEIGHT:
		ProcessParamRTSize(cache);
		*dest = cache->rt_height;
		break;
	case ParamOverrideType::RES_WIDTH:
		*dest = (float)gResolutionInfo.width;
		break;
	case ParamOverrideType::RES_HEIGHT:
		*dest = (float)gResolutionInfo.height;
		break;
	default:
		return false;
	}
	return (*dest != orig);
}

// From DirectXTK with extra formats added
static DXGI_FORMAT EnsureNotTypeless(DXGI_FORMAT fmt)
{
	// Assumes UNORM or FLOAT; doesn't use UINT or SINT
	switch (fmt)
	{
	case DXGI_FORMAT_R32G32B32A32_TYPELESS:    return DXGI_FORMAT_R32G32B32A32_FLOAT;
	case DXGI_FORMAT_R32G32B32_TYPELESS:       return DXGI_FORMAT_R32G32B32_FLOAT;
	case DXGI_FORMAT_R16G16B16A16_TYPELESS:    return DXGI_FORMAT_R16G16B16A16_UNORM;
	case DXGI_FORMAT_R32G32_TYPELESS:          return DXGI_FORMAT_R32G32_FLOAT;
	case DXGI_FORMAT_R10G10B10A2_TYPELESS:     return DXGI_FORMAT_R10G10B10A2_UNORM;
	case DXGI_FORMAT_R8G8B8A8_TYPELESS:        return DXGI_FORMAT_R8G8B8A8_UNORM;
	case DXGI_FORMAT_R16G16_TYPELESS:          return DXGI_FORMAT_R16G16_UNORM;
	case DXGI_FORMAT_R32_TYPELESS:             return DXGI_FORMAT_R32_FLOAT;
	case DXGI_FORMAT_R8G8_TYPELESS:            return DXGI_FORMAT_R8G8_UNORM;
	case DXGI_FORMAT_R16_TYPELESS:             return DXGI_FORMAT_R16_UNORM;
	case DXGI_FORMAT_R8_TYPELESS:              return DXGI_FORMAT_R8_UNORM;
	case DXGI_FORMAT_BC1_TYPELESS:             return DXGI_FORMAT_BC1_UNORM;
	case DXGI_FORMAT_BC2_TYPELESS:             return DXGI_FORMAT_BC2_UNORM;
	case DXGI_FORMAT_BC3_TYPELESS:             return DXGI_FORMAT_BC3_UNORM;
	case DXGI_FORMAT_BC4_TYPELESS:             return DXGI_FORMAT_BC4_UNORM;
	case DXGI_FORMAT_BC5_TYPELESS:             return DXGI_FORMAT_BC5_UNORM;
	case DXGI_FORMAT_B8G8R8A8_TYPELESS:        return DXGI_FORMAT_B8G8R8A8_UNORM;
	case DXGI_FORMAT_B8G8R8X8_TYPELESS:        return DXGI_FORMAT_B8G8R8X8_UNORM;
	case DXGI_FORMAT_BC7_TYPELESS:             return DXGI_FORMAT_BC7_UNORM;
		// Extra depth/stencil buffer formats not covered in DirectXTK (discards
		// stencil buffer to allow binding to a shader resource, alternatively we could
		// discard the depth buffer if we ever needed the stencil buffer):
	case DXGI_FORMAT_R32G8X24_TYPELESS:        return DXGI_FORMAT_R32_FLOAT_X8X24_TYPELESS;
	case DXGI_FORMAT_R24G8_TYPELESS:           return DXGI_FORMAT_R24_UNORM_X8_TYPELESS;
	default:                                   return fmt;
	}
}

// Copy a depth buffer into an input slot of the shader.
// Currently just copies the active depth target - in the future we will
// likely want to be able to copy the depth buffer from elsewhere (especially
// as not all games will have the depth buffer set while drawing UI elements).
// It might also be a good idea to find strategies to reduce the number of
// copies, e.g. by limiting the copy to once per frame, or reusing a resource
// that the game already copied the depth information to.
void AssignDepthInput(ShaderOverride *shaderOverride, bool isPixelShader)
{
	D3D11_DEPTH_STENCIL_VIEW_DESC depth_view_desc;
	D3D11_TEXTURE2D_DESC desc;
	ID3D11DepthStencilView *depth_view = NULL;
	ID3D11ShaderResourceView *resource_view = NULL;
	ID3D11Texture2D *depth_resource = NULL;
	ID3D11Texture2D *resource = NULL;
	HRESULT hr;

	gContext->OMGetRenderTargets(0, NULL, &depth_view);
	if (!depth_view) {
		LogDebug("AssignDepthInput: No depth view\n");
		return;
	}

	depth_view->GetDesc(&depth_view_desc);

	if (depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2D &&
		depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2DMS &&
		depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2DARRAY &&
		depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2DMSARRAY) {
		LogDebug("AssignDepthInput: Depth view not a Texture2D\n");
		goto err_depth_view;
	}

	depth_view->GetResource((ID3D11Resource**)&depth_resource);
	if (!depth_resource) {
		LogDebug("AssignDepthInput: Can't get depth resource\n");
		goto err_depth_view;
	}

	depth_resource->GetDesc(&desc);

	// FIXME: Move cache to context, limit copy to once per frame

	if (desc.Width == shaderOverride->depth_width && desc.Height == shaderOverride->depth_height) {
		gContext->CopyResource(shaderOverride->depth_resource, depth_resource);

		if (isPixelShader)
			gContext->PSSetShaderResources(shaderOverride->depth_input, 1, &shaderOverride->depth_view);
		else
			gContext->VSSetShaderResources(shaderOverride->depth_input, 1, &shaderOverride->depth_view);
	}
	else {
		// Adjust desc to suit a shader resource:
		desc.Usage = D3D11_USAGE_DEFAULT;
		desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
		desc.Format = EnsureNotTypeless(desc.Format);

		hr = gDevice->CreateTexture2D(&desc, NULL, &resource);
		if (FAILED(hr)) {
			LogDebug("AssignDepthInput: Error creating texture: 0x%x\n", hr);
			goto err_depth_resource;
		}

		gContext->CopyResource(resource, depth_resource);

		hr = gDevice->CreateShaderResourceView(resource, NULL, &resource_view);
		if (FAILED(hr)) {
			LogDebug("AssignDepthInput: Error creating resource view: 0x%x\n", hr);
			goto err_resource;
		}

		if (isPixelShader)
			gContext->PSSetShaderResources(shaderOverride->depth_input, 1, &resource_view);
		else
			gContext->VSSetShaderResources(shaderOverride->depth_input, 1, &resource_view);

		if (shaderOverride->depth_resource) {
			shaderOverride->depth_resource->Release();
			shaderOverride->depth_view->Release();
		}

		shaderOverride->depth_resource = resource;
		shaderOverride->depth_view = resource_view;
		shaderOverride->depth_width = desc.Width;
		shaderOverride->depth_height = desc.Height;
	}

	depth_resource->Release();
	depth_view->Release();
	return;

err_resource:
	resource->Release();
err_depth_resource:
	depth_resource->Release();
err_depth_view:
	depth_view->Release();
}

void AssignDummyRenderTarget()
{
	HRESULT hr;
	ID3D11Texture2D *resource = NULL;
	ID3D11RenderTargetView *resource_view = NULL;
	D3D11_TEXTURE2D_DESC desc;
	ID3D11DepthStencilView *depth_view = NULL;
	D3D11_DEPTH_STENCIL_VIEW_DESC depth_view_desc;
	ID3D11Texture2D *depth_resource = NULL;

	gContext->OMGetRenderTargets(0, NULL, &depth_view);

	if (!depth_view) {
		// Might still be able to make a dummy render target of arbitrary size?
		return;
	}

	depth_view->GetDesc(&depth_view_desc);

	if (depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2D &&
		depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2DMS &&
		depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2DARRAY &&
		depth_view_desc.ViewDimension != D3D11_DSV_DIMENSION_TEXTURE2DMSARRAY) {
		goto out;
	}

	depth_view->GetResource((ID3D11Resource**)&depth_resource);
	if (!depth_resource)
		goto out;

	depth_resource->GetDesc(&desc);

	// Adjust desc to suit a render target:
	desc.Usage = D3D11_USAGE_DEFAULT;
	desc.Format = DXGI_FORMAT_R16G16B16A16_FLOAT;
	desc.BindFlags = D3D11_BIND_RENDER_TARGET;

	hr = gDevice->CreateTexture2D(&desc, NULL, &resource);
	if (FAILED(hr))
		goto out1;

	hr = gDevice->CreateRenderTargetView(resource, NULL, &resource_view);
	if (FAILED(hr))
		goto out2;

	gContext->OMSetRenderTargets(1, &resource_view, depth_view);


	resource_view->Release();
out2:
	resource->Release();
out1:
	depth_resource->Release();
out:
	depth_view->Release();
}

void ProcessShaderOverride(ShaderOverride *shaderOverride, bool isPixelShader,
	DrawContext *data, float *separationValue, float *convergenceValue)
{
	D3D11_MAPPED_SUBRESOURCE mappedResource;
	ParamOverrideCache cache;
	bool update_params = false;
	bool use_orig = false;
	int i;

	LogDebug("  override found for shader\n");

	*separationValue = shaderOverride->separation;
	if (*separationValue != FLT_MAX)
		data->override = true;
	*convergenceValue = shaderOverride->convergence;
	if (*convergenceValue != FLT_MAX)
		data->override = true;
	if (shaderOverride->skip == true)
		data->skip = true;

	if (shaderOverride->depth_filter != DepthBufferFilter::NONE) {
		ID3D11DepthStencilView *pDepthStencilView = NULL;

		gContext->OMGetRenderTargets(0, NULL, &pDepthStencilView);

		// Remember - we are NOT switching to the original shader when the condition is true
		if (shaderOverride->depth_filter == DepthBufferFilter::DEPTH_ACTIVE && !pDepthStencilView) {
			use_orig = true;
		}
		else if (shaderOverride->depth_filter == DepthBufferFilter::DEPTH_INACTIVE && pDepthStencilView) {
			use_orig = true;
		}

		if (pDepthStencilView)
			pDepthStencilView->Release();

		// TODO: Add alternate filter type where the depth
		// buffer state is passed as an input to the shader
	}

	if (shaderOverride->partner_hash) {
		if (isPixelShader) {
			if (shaderMapVS[currentVS] != shaderOverride->partner_hash)
				use_orig = true;
		} else {
			if (shaderMapPS[currentPS] != shaderOverride->partner_hash)
				use_orig = true;
		}
	}

	for (i = 0; i < INI_PARAMS_SIZE; i++) {
		update_params |= ProcessParamOverride(&iniParams[i].x, &shaderOverride->x[i], &cache);
		update_params |= ProcessParamOverride(&iniParams[i].y, &shaderOverride->y[i], &cache);
		update_params |= ProcessParamOverride(&iniParams[i].z, &shaderOverride->z[i], &cache);
		update_params |= ProcessParamOverride(&iniParams[i].w, &shaderOverride->w[i], &cache);
	}
	if (update_params) {
		gContext->Map(gIniTexture, 0, D3D11_MAP_WRITE_DISCARD, 0, &mappedResource);
		memcpy(mappedResource.pData, &iniParams, sizeof(iniParams));
		gContext->Unmap(gIniTexture, 0);
	}

	// TODO: Add render target filters, texture filters, etc.

	if (use_orig) {
		if (isPixelShader) {
			auto i = PSmap.find(currentPS);
			if (i != PSmap.end())
				data->oldPixelShader = SwitchPSShader(i->first);
		}
		else {
			auto i = VSmap.find(currentVS);
			if (i != VSmap.end())
				data->oldVertexShader = SwitchVSShader(i->first);
		}
	}
	else {
		if (shaderOverride->fake_o0)
			AssignDummyRenderTarget();

		if (shaderOverride->depth_input)
			AssignDepthInput(shaderOverride, isPixelShader);
	}

}

DrawContext BeforeDraw()
{
	DrawContext data;
	float separationValue = FLT_MAX, convergenceValue = FLT_MAX;

	UINT64 _crc;
	if (currentPS) {
		_crc = shaderMapPS[currentPS];
		if (_crc == PS_hash)
			data.skip = true;
	}
	if (currentVS) {
		_crc = shaderMapVS[currentVS];
		if (_crc == VS_hash)
			data.skip = true;
	}

	UINT64 mCurrentVertexShader = shaderMapVS[currentVS];
	ShaderOverrideMap::iterator iVertex = mShaderOverrideMap.find(mCurrentVertexShader);
	UINT64 mCurrentPixelShader = shaderMapPS[currentPS];
	ShaderOverrideMap::iterator iPixel = mShaderOverrideMap.find(mCurrentPixelShader);	

	if (iVertex != mShaderOverrideMap.end())
		ProcessShaderOverride(&iVertex->second, false, &data, &separationValue, &convergenceValue);
	if (iPixel != mShaderOverrideMap.end())
		ProcessShaderOverride(&iPixel->second, true, &data, &separationValue, &convergenceValue);

	return data;
}

void AfterDraw(DrawContext &data)
{
	if (data.skip)
		return;

	if (data.oldVertexShader) {
		ID3D11VertexShader *ret;
		ret = SwitchVSShader(data.oldVertexShader);
		data.oldVertexShader->Release();
		if (ret)
			ret->Release();
	}
	if (data.oldPixelShader) {
		ID3D11PixelShader *ret;
		ret = SwitchPSShader(data.oldPixelShader);
		data.oldPixelShader->Release();
		if (ret)
			ret->Release();
	}
}
#pragma endregion

#pragma region draw
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

#pragma region Button
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
		}
		else {
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
		}
		else if (XKey == 0x800) {
			if (state.Gamepad.bRightTrigger > XINPUT_GAMEPAD_TRIGGER_THRESHOLD && oldState.Gamepad.bRightTrigger <= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
				status = buttonPress::Down;;
			if (state.Gamepad.bRightTrigger < XINPUT_GAMEPAD_TRIGGER_THRESHOLD && oldState.Gamepad.bRightTrigger >= XINPUT_GAMEPAD_TRIGGER_THRESHOLD)
				status = buttonPress::Up;
		}
		else {
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
	}
	else {
		return new keyboardMouseKey(key);
	}
}

void HuntBeep() {
	BeepShort();
}

void reloadFixes() {
	WIN32_FIND_DATA findFileData;
	char path[MAX_PATH];
	char buffer[80];

	path[0] = 0;
	strcat_s(path, MAX_PATH, cwd);
	strcat_s(path, MAX_PATH, "\\ShaderFixes\\????????????????-*.txt");
	HANDLE hFind = FindFirstFile(path, &findFileData);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			string s = findFileData.cFileName;
			string sHash = s.substr(0, 16);
			UINT64 _crc = stoull(sHash, NULL, 16);
			if (!crc2.count(_crc))
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
				HRESULT res = sCreatePixelShader_Hook.fnCreatePixelShader(gDevice, byteCode.data(), byteCode.size(), NULL, &pPixelShader);
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
				HRESULT res = sCreateVertexShader_Hook.fnCreateVertexShader(gDevice, byteCode.data(), byteCode.size(), NULL, &pVertexShader);
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
					HRESULT res = sCreateVertexShader_Hook.fnCreateVertexShader(gDevice, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), NULL, &pVertexShader);
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
					HRESULT res = sCreatePixelShader_Hook.fnCreatePixelShader(gDevice, pByteCode->GetBufferPointer(), pByteCode->GetBufferSize(), NULL, &pPixelShader);
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
			if (PresentPS.size() == 0) {
				PS_hash = -1;
				HuntBeep();
			} else {
				if (!strcmp(Command.c_str(), "next_pixelshader")) {
					if (PS_hash == -1) {
						PS_hash = PresentPS.begin()->first;
					} else {
						auto it = PresentPS.find(PS_hash);
						if (it != PresentPS.end()) {
							int i = 1;
							for (auto it2 = PresentPS.begin(); it2 != it; it2++)
								i++;
							if (i == PresentPS.size()) {
								PS_hash = -1;
								HuntBeep();
							} else {
								it++;
								PS_hash = it->first;
							}
						} else {
							UINT64 orig_hash = PS_hash;
							for (auto it = PresentPS.begin(); it != PresentPS.end(); it++) {
								if (it->first > PS_hash) {
									PS_hash = it->first;
									break;
								}
							}
							if (PS_hash == orig_hash) {
								PS_hash = -1;
								HuntBeep();
							}
						}
					}
				}
				if (!strcmp(Command.c_str(), "previous_pixelshader")) {
					if (PS_hash == -1) {
						PS_hash = PresentPS.rbegin()->first;
					} else {
						auto it = PresentPS.find(PS_hash);
						if (it != PresentPS.end()) {
							int i = 1;
							for (auto it2 = PresentPS.begin(); it2 != it; it2++)
								i++;
							if (i == 1) {
								PS_hash = -1;
								HuntBeep();
							} else {
								it--;
								PS_hash = it->first;
							}
						} else {
							UINT64 orig_hash = PS_hash;
							for (auto it = PresentPS.rbegin(); it != PresentPS.rend(); it++) {
								if (it->first < PS_hash) {
									PS_hash = it->first;
									break;
								}
							}
							if (PS_hash == orig_hash) {
								PS_hash = -1;
								HuntBeep();
							}
						}
					}
				}
				if (!strcmp(Command.c_str(), "mark_pixelshader")) {
					path[0] = 0;
					strcat_s(path, MAX_PATH, cwd);
					strcat_s(path, MAX_PATH, "\\Mark");
					CreateDirectory(path, NULL);
					
					auto _crc = PS_hash;
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
			}
			if (PresentVS.size() == 0) {
				VS_hash = -1;
				HuntBeep();
			} else {
				if (!strcmp(Command.c_str(), "next_vertexshader")) {
					if (VS_hash == -1) {
						VS_hash = PresentVS.begin()->first;
					} else {
						auto it = PresentVS.find(VS_hash);
						if (it != PresentVS.end()) {
							int i = 1;
							for (auto it2 = PresentVS.begin(); it2 != it; it2++)
								i++;
							if (i == PresentVS.size()) {
								VS_hash = -1;
								HuntBeep();
							} else {
								it++;
								VS_hash = it->first;
							}
						} else {
							UINT64 orig_hash = VS_hash;
							for (auto it = PresentVS.begin(); it != PresentVS.end(); it++) {
								if (it->first > VS_hash) {
									VS_hash = it->first;
									break;
								}
							}
							if (VS_hash == orig_hash) {
								VS_hash = -1;
								HuntBeep();
							}
						}
					}
				}
				if (!strcmp(Command.c_str(), "previous_vertexshader")) {
					if (VS_hash == -1) {
						VS_hash = PresentVS.rbegin()->first;
					} else {
						auto it = PresentVS.find(VS_hash);
						if (it != PresentVS.end()) {
							int i = 1;
							for (auto it2 = PresentVS.begin(); it2 != it; it2++)
								i++;
							if (i == 1) {
								VS_hash = -1;
								HuntBeep();
							} else {
								it--;
								VS_hash = it->first;
							}
						} else {
							UINT64 orig_hash = VS_hash;
							for (auto it = PresentVS.rbegin(); it != PresentVS.rend(); it++) {
								if (it->first < VS_hash) {
									VS_hash = it->first;
									break;
								}
							}
							if (VS_hash == orig_hash) {
								VS_hash = -1;
								HuntBeep();
							}
						}
					}
				}
				if (!strcmp(Command.c_str(), "mark_vertexshader")) {
					path[0] = 0;
					strcat_s(path, MAX_PATH, cwd);
					strcat_s(path, MAX_PATH, "\\Mark");
					CreateDirectory(path, NULL);
					
					auto _crc = VS_hash;
					char buffer[80];
					sprintf_s(buffer, 80, "\\Mark\\%016llX-v.bin", _crc);
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
			}
			if (!strcmp(Command.c_str(), "reload_fixes")) {
				reloadFixes();
			}
		}
		if (status == buttonPress::Down && !strcmp(Command.c_str(), "toggle_hunting")) {
			PS_hash = -1;
			VS_hash = -1;
			gl_hunt = !gl_hunt;
			HuntBeep();
			LogInfo("toggle_hunting %d\n", gl_hunt);
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
		SavedValue = readVariable();
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
				if (curDelay > 0)
					curDelay = 0; // cancel delayed keypress
				if (curTransition > 0)
					curTransition = 0; // cancel transition
				else
					SavedValue = readVariable();
				toggleDown = false;
				Store = Value;
			} else {
				if (curDelay > 0)
					curDelay = 0; // cancel delayed keypress
				if (curTransition > 0)
					curTransition = 0; // cancel transition
				toggleDown = true;
				Store = SavedValue;
			}
		} else if (Type == KeyType::Hold) {
			if (curDelayUp > 0 || curDelay > 0) {
				curDelay = 0;
				curDelayUp = 0; // cancel delayed keypress
			}
			if (curTransitionUp > 0 || curTransition > 0) {
				curTransition = 0;
				curTransitionUp = 0; // cancel transition
			} else {
				SavedValue = readVariable();
			}
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
		if (Variable & 0x01) f[0] = iniParams[0].x;
		if (Variable & 0x02) f[1] = iniParams[0].y;
		if (Variable & 0x04) f[2] = iniParams[0].z;
		if (Variable & 0x08) f[3] = iniParams[0].w;
		if (Variable & 0x10) NvAPI_Stereo_GetConvergence(gStereoHandle, &f[4]);
		if (Variable & 0x20) NvAPI_Stereo_GetSeparation(gStereoHandle, &f[5]);
		return f;
	}
	void setVariable(vector<float> f) {
		if (Variable & 0x01) iniParams[0].x = f[0];
		if (Variable & 0x02) iniParams[0].y = f[1];
		if (Variable & 0x04) iniParams[0].z = f[2];
		if (Variable & 0x08) iniParams[0].w = f[3];
		if (Variable & 0x10) {
			if (gl_nvapi)
				NvAPIOverride();
			NvAPI_Stereo_SetConvergence(gStereoHandle, f[4]);
		}
		if (Variable & 0x20) {
			if (gl_nvapi)
				NvAPIOverride();
			NvAPI_Stereo_SetSeparation(gStereoHandle, f[5]);
		}
		if (Variable & 0x0F) {
			D3D11_MAPPED_SUBRESOURCE mappedResource;
			gContext->Map(gIniTexture, 0, D3D11_MAP_WRITE_DISCARD, 0, &mappedResource);
			memcpy(mappedResource.pData, &iniParams, sizeof(iniParams));
			gContext->Unmap(gIniTexture, 0);
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

#pragma region DXGI
HRESULT STDMETHODCALLTYPE DXGIH_Present(IDXGISwapChain* This, UINT SyncInterval, UINT Flags) {
	frameFunction();
	if (RunningVS.size() == 0 && RunningPS.size() == 0) {
		LogInfo("Present empty\n");
	} else {
		PresentPS.clear();
		PresentVS.clear();
		for (auto i = RunningVS.begin(); i != RunningVS.end(); i++) {
			PresentVS[i->first] = i->second;
		}
		for (auto i = RunningPS.begin(); i != RunningPS.end(); i++) {
			PresentPS[i->first] = i->second;
		}
		RunningPS.clear();
		RunningVS.clear();
		LogInfo("Present: VS %zd PS %zd\n", PresentVS.size(), PresentPS.size());
	}
	if (gDevice && gContext) {
		gStereoTexMgr->UpdateStereoTexture(gDevice, gContext, gStereoTexture, false);
	}
	return sDXGI_Present_Hook.fnDXGI_Present(This, SyncInterval, Flags);
}

HRESULT STDMETHODCALLTYPE DXGIH_ResizeBuffers(IDXGISwapChain* This, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags) {
	HRESULT hr = sDXGI_ResizeBuffers_Hook.fnDXGI_ResizeBuffers(This, BufferCount, Width, Height, NewFormat, SwapChainFlags);

	if (SUCCEEDED(hr) && gResolutionInfo.from == GetResolutionFrom::SWAP_CHAIN) {
		gResolutionInfo.width = Width;
		gResolutionInfo.height = Height;
		LogInfo("Got resolution from swap chain: %ix%i\n",
			gResolutionInfo.width, gResolutionInfo.height);
	}
	return hr;
}

HRESULT STDMETHODCALLTYPE DXGI_CreateSwapChain1(IDXGIFactory1 * This, IUnknown * pDevice, DXGI_SWAP_CHAIN_DESC * pDesc, IDXGISwapChain ** ppSwapChain) {
	LogInfo("CreateSwapChain\n");
	HRESULT hr = sCreateSwapChain_Hook.fnCreateSwapChain1(This, pDevice, pDesc, ppSwapChain);
	if (!gl_Present_hooked) {
		LogInfo("Present hooked\n");
		gl_Present_hooked = true;
		DWORD_PTR*** vTable = (DWORD_PTR***)*ppSwapChain;
		DXGI_Present origPresent = (DXGI_Present)(*vTable)[8];
		DXGI_ResizeBuffers origResizeBuffers = (DXGI_ResizeBuffers)(*vTable)[13];
		cHookMgr.Hook(&(sDXGI_Present_Hook.nHookId), (LPVOID*)&(sDXGI_Present_Hook.fnDXGI_Present), origPresent, DXGIH_Present);
		cHookMgr.Hook(&(sDXGI_ResizeBuffers_Hook.nHookId), (LPVOID*)&(sDXGI_ResizeBuffers_Hook.fnDXGI_ResizeBuffers), origResizeBuffers, DXGIH_ResizeBuffers);

		if (pDesc && gResolutionInfo.from == GetResolutionFrom::SWAP_CHAIN) {
			gResolutionInfo.width = pDesc->BufferDesc.Width;
			gResolutionInfo.height = pDesc->BufferDesc.Height;
			LogInfo("Got resolution from swap chain: %ix%i\n",
				gResolutionInfo.width, gResolutionInfo.height);
		}
	}
	return hr;
}

void HackedPresent(ID3D11Device *pDevice) {
	IDXGIFactory1 * pFactory;
	HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)(&pFactory));
	DWORD_PTR*** vTable = (DWORD_PTR***)pFactory;
	DXGI_CSC1 origCSC1 = (DXGI_CSC1)(*vTable)[10];
	cHookMgr.Hook(&(sCreateSwapChain_Hook.nHookId), (LPVOID*)&(sCreateSwapChain_Hook.fnCreateSwapChain1), origCSC1, DXGI_CreateSwapChain1);
	pFactory->Release();
}
#pragma endregion

#pragma region Texture
void STDMETHODCALLTYPE D3D11C_CopySubresourceRegion(ID3D11DeviceContext * This, ID3D11Resource *pDstResource, UINT DstSubresource, UINT DstX, UINT DstY, UINT DstZ, ID3D11Resource *pSrcResource, UINT SrcSubresource, const D3D11_BOX *pSrcBox)
{
	D3D11_BOX replaceSrcBox;
	UINT replaceDstX = DstX;

	if (ExpandRegionCopy(pDstResource, DstX, DstY, pSrcResource, pSrcBox, &replaceDstX, &replaceSrcBox))
		pSrcBox = &replaceSrcBox;

	sCopySubresourceRegion_Hook.fnCopySubresourceRegion(This, pDstResource, DstSubresource, replaceDstX, DstY, DstZ, pSrcResource, SrcSubresource, pSrcBox);
}
/*
* Used for CryEngine games like Lichdom that copy a 2D rectangle from the
* colour render target to a texture as an input for transparent refraction
* effects. Expands the rectange to the full width.
*/
bool ExpandRegionCopy(ID3D11Resource *pDstResource, UINT DstX,
	UINT DstY, ID3D11Resource *pSrcResource, const D3D11_BOX *pSrcBox,
	UINT *replaceDstX, D3D11_BOX *replaceBox)
{
	ID3D11Texture2D *srcTex = (ID3D11Texture2D*)pSrcResource;
	ID3D11Texture2D *dstTex = (ID3D11Texture2D*)pDstResource;
	D3D11_TEXTURE2D_DESC srcDesc, dstDesc;
	D3D11_RESOURCE_DIMENSION srcDim, dstDim;
	UINT64 srcHash, dstHash;
	TextureOverrideMap::iterator i;

	if (!pSrcResource || !pDstResource || !pSrcBox)
		return false;

	pSrcResource->GetType(&srcDim);
	pDstResource->GetType(&dstDim);
	if (srcDim != dstDim || srcDim != D3D11_RESOURCE_DIMENSION_TEXTURE2D)
		return false;

	srcTex->GetDesc(&srcDesc);
	dstTex->GetDesc(&dstDesc);
	srcHash = GetTexture2DHash(srcTex, false, NULL);
	dstHash = GetTexture2DHash(dstTex, false, NULL);

	LogDebug("CopySubresourceRegion %016I64x (%u:%u x %u:%u / %u x %u) -> %016I64x (%u x %u / %u x %u)\n",
		srcHash, pSrcBox->left, pSrcBox->right, pSrcBox->top, pSrcBox->bottom,
		srcDesc.Width, srcDesc.Height, dstHash, DstX, DstY, dstDesc.Width, dstDesc.Height);

	i = mTextureOverrideMap.find(dstHash);
	if (i == mTextureOverrideMap.end())
		return false;

	if (!i->second.expand_region_copy)
		return false;

	memcpy(replaceBox, pSrcBox, sizeof(D3D11_BOX));
	*replaceDstX = 0;
	replaceBox->left = 0;
	replaceBox->right = dstDesc.Width;

	return true;
}

static void CheckSpecialCaseTextureResolution(UINT width, UINT height, int *hashWidth, int *hashHeight)
{
	if (width == gResolutionInfo.width && height == gResolutionInfo.height) {
		*hashWidth = 1386492276;
		*hashHeight = 1386492276;
	}
	else if (width == gResolutionInfo.width * 2 && height == gResolutionInfo.height * 2) {
		*hashWidth = 1108431669;
		*hashHeight = 1108431669;
	}
	else if (width == gResolutionInfo.width * 4 && height == gResolutionInfo.height * 4) {
		*hashWidth = 1167952304;
		*hashHeight = 1167952304;
	}
	else if (width == gResolutionInfo.width * 8 && height == gResolutionInfo.height * 8) {
		*hashWidth = 3503946005;
		*hashHeight = 3503946005;
	}
	else if (width == gResolutionInfo.width / 2 && height == gResolutionInfo.height / 2) {
		*hashWidth = 1599678497;
		*hashHeight = 1599678497;
	}
}

static UINT64 CalcTexture2DDescHash(const D3D11_TEXTURE2D_DESC *desc,
	UINT64 initial_hash, int override_width, int override_height)
{
	UINT64 hash = initial_hash;

	if (override_width)
		hash ^= override_width;
	else
		hash ^= desc->Width;
	hash *= FNV_64_PRIME;

	if (override_height)
		hash ^= override_height;
	else
		hash ^= desc->Height;
	hash *= FNV_64_PRIME;

	hash ^= desc->MipLevels; hash *= FNV_64_PRIME;
	hash ^= desc->ArraySize; hash *= FNV_64_PRIME;
	hash ^= desc->Format; hash *= FNV_64_PRIME;
	hash ^= desc->SampleDesc.Count;
	hash ^= desc->SampleDesc.Quality;
	hash ^= desc->Usage; hash *= FNV_64_PRIME;
	hash ^= desc->BindFlags; hash *= FNV_64_PRIME;
	hash ^= desc->CPUAccessFlags; hash *= FNV_64_PRIME;
	hash ^= desc->MiscFlags;

	return hash;
}

HRESULT STDMETHODCALLTYPE D3D11_CreateTexture2D(ID3D11Device * This, const D3D11_TEXTURE2D_DESC *pDesc, const D3D11_SUBRESOURCE_DATA *pInitialData, ID3D11Texture2D **ppTexture2D) {
	TextureOverride *textureOverride = NULL;
	bool override = false;

	// Rectangular depth stencil textures of at least 640x480 may indicate
	// the game's resolution, for games that upscale to their swap chains:
	if (pDesc && (pDesc->BindFlags & D3D11_BIND_DEPTH_STENCIL) &&
		gResolutionInfo.from == GetResolutionFrom::DEPTH_STENCIL &&
		pDesc->Width >= 640 && pDesc->Height >= 480 && pDesc->Width != pDesc->Height) {
		gResolutionInfo.width = pDesc->Width;
		gResolutionInfo.height = pDesc->Height;
		LogInfo("Got resolution from depth/stencil buffer: %ix%i\n",
			gResolutionInfo.width, gResolutionInfo.height);
	}

	// Get screen resolution.
	int hashWidth = 0;
	int hashHeight = 0;
	if (pDesc && gResolutionInfo.from != GetResolutionFrom::INVALID)
		CheckSpecialCaseTextureResolution(pDesc->Width, pDesc->Height, &hashWidth, &hashHeight);

	// Create hash code.  Wrapped in try/catch because it can crash in Dirt Rally,
	// because of noncontiguous or non-mapped memory for the texture.  Not sure this
	// is the best strategy.
	UINT64 hash = 0;
	if (pInitialData && pInitialData->pSysMem && pDesc)
		try
	{
		hash = fnv_64_buf(pInitialData->pSysMem, pDesc->Width / 2 * pDesc->Height * pDesc->ArraySize);
	}
	catch (...)
	{
		// Fatal error, but catch it and return null for hash.
		LogInfo("   ******* Exception caught while calculating Texture2D hash ****** \n");
		hash = 0;
	}

	if (pDesc)
		hash = CalcTexture2DDescHash(pDesc, hash, hashWidth, hashHeight);

	// Override custom settings?
	NVAPI_STEREO_SURFACECREATEMODE oldMode = (NVAPI_STEREO_SURFACECREATEMODE)-1, newMode = (NVAPI_STEREO_SURFACECREATEMODE)-1;
	D3D11_TEXTURE2D_DESC newDesc = *pDesc;

	TextureOverrideMap::iterator i = mTextureOverrideMap.find(hash);
	if (i != mTextureOverrideMap.end()) {
		textureOverride = &i->second;

		override = true;
		if (textureOverride->stereoMode != -1)
			newMode = (NVAPI_STEREO_SURFACECREATEMODE)textureOverride->stereoMode;
	}

	if (pDesc && gSurfaceSquareCreateMode >= 0 && pDesc->Width == pDesc->Height && (pDesc->Usage & D3D11_USAGE_IMMUTABLE) == 0)
	{
		override = true;
		newMode = (NVAPI_STEREO_SURFACECREATEMODE)gSurfaceSquareCreateMode;
	}
	if (override)
	{
		if (newMode != (NVAPI_STEREO_SURFACECREATEMODE)-1)
		{
			NvAPI_Stereo_GetSurfaceCreationMode(gStereoHandle, &oldMode);
			NvAPIOverride();
			LogInfo("  setting custom surface creation mode.\n");

			if (NVAPI_OK != NvAPI_Stereo_SetSurfaceCreationMode(gStereoHandle, newMode))
			{
				LogInfo("    call failed.\n");
			}
		}
		if (textureOverride && textureOverride->format != -1)
		{
			LogInfo("  setting custom format to %d\n", textureOverride->format);

			newDesc.Format = (DXGI_FORMAT)textureOverride->format;
		}
	}

	// Actual creation:
	HRESULT hr = sCreateTexture2D_Hook.fnCreateTexture2D(This, pDesc, pInitialData, ppTexture2D);
	if (oldMode != (NVAPI_STEREO_SURFACECREATEMODE)-1)
	{
		if (NVAPI_OK != NvAPI_Stereo_SetSurfaceCreationMode(gStereoHandle, oldMode))
		{
			LogInfo("    restore call failed.\n");
		}
	}
	if (ppTexture2D) LogDebug("  returns result = %x, handle = %p\n", hr, *ppTexture2D);

	// Register texture.
	if (ppTexture2D)
	{
		mTexture2D_ID[*ppTexture2D] = hash;
	}
	return hr;
}

static UINT64 CalcTexture3DDescHash(const D3D11_TEXTURE3D_DESC *desc,
	UINT64 initial_hash, int override_width, int override_height)
{
	UINT64 hash = initial_hash;

	// Same comment as in CalcTexture2DDescHash above - concerned about
	// inconsistent use of these resolution overrides
	if (override_width)
		hash ^= override_width;
	else
		hash ^= desc->Width;
	hash *= FNV_64_PRIME;

	if (override_height)
		hash ^= override_height;
	else
		hash ^= desc->Height;
	hash *= FNV_64_PRIME;

	hash ^= desc->Depth; hash *= FNV_64_PRIME;
	hash ^= desc->MipLevels; hash *= FNV_64_PRIME;
	hash ^= desc->Format; hash *= FNV_64_PRIME;
	hash ^= desc->Usage; hash *= FNV_64_PRIME;
	hash ^= desc->BindFlags; hash *= FNV_64_PRIME;
	hash ^= desc->CPUAccessFlags; hash *= FNV_64_PRIME;
	hash ^= desc->MiscFlags;

	return hash;
}

UINT64 GetTexture2DHash(ID3D11Texture2D *texture,
	bool log_new, struct ResourceInfo *resource_info)
{

	D3D11_TEXTURE2D_DESC desc;
	std::unordered_map<ID3D11Texture2D *, UINT64>::iterator j;

	texture->GetDesc(&desc);

	if (resource_info)
		*resource_info = desc;

	j = mTexture2D_ID.find(texture);
	if (j != mTexture2D_ID.end())
		return j->second;

	return CalcTexture2DDescHash(&desc, 0, 0, 0);
}

UINT64 GetTexture3DHash(ID3D11Texture3D *texture,
	bool log_new, struct ResourceInfo *resource_info)
{

	D3D11_TEXTURE3D_DESC desc;
	std::unordered_map<ID3D11Texture3D *, UINT64>::iterator j;

	texture->GetDesc(&desc);

	if (resource_info)
		*resource_info = desc;

	j = mTexture3D_ID.find(texture);
	if (j != mTexture3D_ID.end())
		return j->second;

	return CalcTexture3DDescHash(&desc, 0, 0, 0);
}

UINT64 GetTexture3DHash(ID3D11Texture3D *texture,
	struct ResourceInfo *resource_info)
{

	D3D11_TEXTURE3D_DESC desc;
	std::unordered_map<ID3D11Texture3D *, UINT64>::iterator j;

	texture->GetDesc(&desc);

	if (resource_info)
		*resource_info = desc;


	j = mTexture3D_ID.find(texture);
	if (j != mTexture3D_ID.end())
		return j->second;
	return CalcTexture3DDescHash(&desc, 0, 0, 0);
}

HRESULT STDMETHODCALLTYPE D3D11_CreateTexture3D(ID3D11Device * This, const D3D11_TEXTURE3D_DESC *pDesc, const D3D11_SUBRESOURCE_DATA *pInitialData, ID3D11Texture3D **ppTexture3D) {
	// Rectangular depth stencil textures of at least 640x480 may indicate
	// the game's resolution, for games that upscale to their swap chains:
	if (pDesc && (pDesc->BindFlags & D3D11_BIND_DEPTH_STENCIL) &&
		gResolutionInfo.from == GetResolutionFrom::DEPTH_STENCIL &&
		pDesc->Width >= 640 && pDesc->Height >= 480 && pDesc->Width != pDesc->Height) {
		gResolutionInfo.width = pDesc->Width;
		gResolutionInfo.height = pDesc->Height;
		LogInfo("Got resolution from depth/stencil buffer: %ix%i\n",
			gResolutionInfo.width, gResolutionInfo.height);
	}

	// Get screen resolution.
	int hashWidth = 0;
	int hashHeight = 0;
	if (pDesc && gResolutionInfo.from != GetResolutionFrom::INVALID)
		CheckSpecialCaseTextureResolution(pDesc->Width, pDesc->Height, &hashWidth, &hashHeight);

	// Create hash code.
	UINT64 hash = 0;
	if (pInitialData && pInitialData->pSysMem)
		hash = fnv_64_buf(pInitialData->pSysMem, pDesc->Width / 2 * pDesc->Height * pDesc->Depth);
	if (pDesc)
		hash = CalcTexture3DDescHash(pDesc, hash, hashWidth, hashHeight);
	//LogInfo("  InitialData = %p, hash = %16llx\n", pInitialData, hash);

	HRESULT hr = sCreateTexture3D_Hook.fnCreateTexture3D(This, pDesc, pInitialData, ppTexture3D);

	// Register texture.
	if (hr == S_OK && ppTexture3D) {
		mTexture3D_ID[*ppTexture3D] = hash;
	}

	//LogInfo("  returns result = %x\n", hr);

	return hr;
}
#pragma endregion

#pragma region Hooks
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
	d3d11->CreateTexture2D(&desc, NULL, &gStereoTexture);

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
	d3d11->CreateShaderResourceView(gStereoTexture, &descRV, &gStereoResourceView);

	return S_OK;
}

void CreateINITexture(ID3D11Device* d3d11) {
	D3D11_TEXTURE1D_DESC desc;
	memset(&desc, 0, sizeof(D3D11_TEXTURE1D_DESC));
	D3D11_SUBRESOURCE_DATA initialData;
	initialData.pSysMem = &iniParams;
	initialData.SysMemPitch = sizeof(DirectX::XMFLOAT4) * INI_PARAMS_SIZE;	// only one 4 element struct

	desc.Width = 1;												// 1 texel, .rgba as a float4
	desc.MipLevels = 1;
	desc.ArraySize = 1;
	desc.Format = DXGI_FORMAT_R32G32B32A32_FLOAT;	// float4
	desc.Usage = D3D11_USAGE_DYNAMIC;				// Read/Write access from GPU and CPU
	desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;		// As resource view, access via t120
	desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;		// allow CPU access for hotkeys
	desc.MiscFlags = 0;
	HRESULT ret = d3d11->CreateTexture1D(&desc, &initialData, &gIniTexture);
	// Since we need to bind the texture to a shader input, we also need a resource view.
	// The pDesc is set to NULL so that it will simply use the desc format above.
	D3D11_SHADER_RESOURCE_VIEW_DESC descRV;
	memset(&descRV, 0, sizeof(D3D11_SHADER_RESOURCE_VIEW_DESC));
	ret = d3d11->CreateShaderResourceView(gIniTexture, NULL, &gIniResourceView);
}

void InitializeStereo(ID3D11Device * pDevice) {
	gDevice = pDevice;
	if (NVAPI_OK != NvAPI_Stereo_CreateHandleFromIUnknown(gDevice, &gStereoHandle))
		gStereoHandle = 0;
	CreateINITexture(gDevice);
	// Create our stereo parameter texture
	CreateStereoParamTextureAndView(gDevice);
	// Initialize the stereo texture manager. Note that the StereoTextureManager was created
	// before the device. This is important, because NvAPI_Stereo_CreateConfigurationProfileRegistryKey
	// must be called BEFORE device creation.
	gStereoTexMgr->Init(gDevice);
	LogInfo("Stereo Initialized\n");
}

HRESULT MapDenyCPURead(
	ID3D11DeviceContext * This,
	ID3D11Resource *pResource,
	UINT Subresource,
	D3D11_MAP MapType,
	UINT MapFlags,
	D3D11_MAPPED_SUBRESOURCE *pMappedResource)
{
	ID3D11Texture2D *tex = (ID3D11Texture2D*)pResource;
	D3D11_TEXTURE2D_DESC desc;
	D3D11_RESOURCE_DIMENSION dim;
	UINT64 hash;
	TextureOverrideMap::iterator i;
	HRESULT hr;
	UINT replace_size;
	void *replace;

	if (!pResource || (MapType != D3D11_MAP_READ && MapType != D3D11_MAP_READ_WRITE))
		return E_FAIL;

	pResource->GetType(&dim);
	if (dim != D3D11_RESOURCE_DIMENSION_TEXTURE2D)
		return E_FAIL;

	tex->GetDesc(&desc);
	hash = GetTexture2DHash(tex, false, NULL);

	LogDebug("Map Texture2D %016I64x (%ux%u) Subresource=%u MapType=%i MapFlags=%u\n",
		hash, desc.Width, desc.Height, Subresource, MapType, MapFlags);

	// Currently only replacing first subresource to simplify map type, and
	// only on read access as it is unclear how to handle a read/write access.
	// Still log others in case we find we need them later.
	if (Subresource != 0 || MapType != D3D11_MAP_READ)
		return E_FAIL;

	i = mTextureOverrideMap.find(hash);
	if (i == mTextureOverrideMap.end())
		return E_FAIL;

	if (!i->second.deny_cpu_read)
		return E_FAIL;

	// TODO: We can probably skip the original map call altogether avoiding
	// the latency so long as the D3D11_MAPPED_SUBRESOURCE we return is sane.
	hr = sMap_Hook.fnMap(This, pResource, Subresource, MapType, MapFlags, pMappedResource);

	if (SUCCEEDED(hr) && pMappedResource->pData) {
		replace_size = pMappedResource->RowPitch * desc.Height;
		replace = malloc(replace_size);
		if (!replace) {
			LogDebug("deny_cpu_read out of memory\n");
			return E_OUTOFMEMORY;
		}
		memset(replace, 0, replace_size);
		mDeniedMaps[pResource] = replace;
		LogDebug("deny_cpu_read replaced mapping from 0x%p with %u bytes of 0s at 0x%p\n",
			pMappedResource->pData, replace_size, replace);
		pMappedResource->pData = replace;
	}

	return hr;
}

void FreeDeniedMapping(ID3D11Resource *pResource, UINT Subresource)
{
	if (Subresource != 0)
		return;

	DeniedMap::iterator i;
	i = mDeniedMaps.find(pResource);
	if (i == mDeniedMaps.end())
		return;

	LogDebug("deny_cpu_read freeing map at 0x%p\n", i->second);

	free(i->second);
	mDeniedMaps.erase(i);
}

HRESULT STDMETHODCALLTYPE D3D11C_Map(ID3D11DeviceContext * This, ID3D11Resource *pResource, UINT Subresource, D3D11_MAP MapType, UINT MapFlags, D3D11_MAPPED_SUBRESOURCE *pMappedResource) {
	HRESULT hr = MapDenyCPURead(This, pResource, Subresource, MapType, MapFlags, pMappedResource);
	if (SUCCEEDED(hr))
		return hr;

	return sMap_Hook.fnMap(This, pResource, Subresource, MapType, MapFlags, pMappedResource);
}

void STDMETHODCALLTYPE D3D11C_Unmap(ID3D11DeviceContext * This, ID3D11Resource *pResource, UINT Subresource) {
	FreeDeniedMapping(pResource, Subresource);
	sUnmap_Hook.fnUnmap(This, pResource, Subresource);
}

void hook(ID3D11DeviceContext** ppContext) {
	if (ppContext != NULL && *ppContext != NULL) {
		LogInfo("Context Hook: %p\n", *ppContext);
		if (!gl_hookedContext) {
			gl_hookedContext = true;
			DWORD_PTR*** vTable = (DWORD_PTR***)*ppContext;
			D3D11C_PSSS origPSSS = (D3D11C_PSSS)(*vTable)[9];
			D3D11C_VSSS origVSSS = (D3D11C_VSSS)(*vTable)[11];
			D3D11C_GSSS origGSSS = (D3D11C_GSSS)(*vTable)[23];
			D3D11C_HSSS origHSSS = (D3D11C_HSSS)(*vTable)[60];
			D3D11C_DSSS origDSSS = (D3D11C_DSSS)(*vTable)[64];
			D3D11C_CSSS origCSSS = (D3D11C_CSSS)(*vTable)[69];

			D3D11C_CSR origCSR = (D3D11C_CSR)(*vTable)[46];
			D3D11C_MAP origMAP = (D3D11C_MAP)(*vTable)[14];
			D3D11C_UNMAP origUNMAP = (D3D11C_UNMAP)(*vTable)[15];
			
			cHookMgr.Hook(&(sMap_Hook.nHookId), (LPVOID*)&(sMap_Hook.fnMap), origMAP, D3D11C_Map);
			cHookMgr.Hook(&(sUnmap_Hook.nHookId), (LPVOID*)&(sUnmap_Hook.fnUnmap), origUNMAP, D3D11C_Unmap);
			cHookMgr.Hook(&(sCopySubresourceRegion_Hook.nHookId), (LPVOID*)&(sCopySubresourceRegion_Hook.fnCopySubresourceRegion), origCSR, D3D11C_CopySubresourceRegion);

			cHookMgr.Hook(&(sPSSetShader_Hook.nHookId), (LPVOID*)&(sPSSetShader_Hook.fnPSSetShader), origPSSS, D3D11C_PSSetShader);
			cHookMgr.Hook(&(sVSSetShader_Hook.nHookId), (LPVOID*)&(sVSSetShader_Hook.fnVSSetShader), origVSSS, D3D11C_VSSetShader);
			cHookMgr.Hook(&(sGSSetShader_Hook.nHookId), (LPVOID*)&(sGSSetShader_Hook.fnGSSetShader), origGSSS, D3D11C_GSSetShader);
			cHookMgr.Hook(&(sHSSetShader_Hook.nHookId), (LPVOID*)&(sHSSetShader_Hook.fnHSSetShader), origHSSS, D3D11C_HSSetShader);
			cHookMgr.Hook(&(sDSSetShader_Hook.nHookId), (LPVOID*)&(sDSSetShader_Hook.fnDSSetShader), origDSSS, D3D11C_DSSetShader);
			cHookMgr.Hook(&(sCSSetShader_Hook.nHookId), (LPVOID*)&(sCSSetShader_Hook.fnCSSetShader), origCSSS, D3D11C_CSSetShader);

			D3D11C_Draw origDraw = (D3D11C_Draw)(*vTable)[13];
			D3D11C_DrawAuto origDrawAuto = (D3D11C_DrawAuto)(*vTable)[38];
			D3D11C_DrawIndexed origDrawIndexed = (D3D11C_DrawIndexed)(*vTable)[12];
			D3D11C_DrawInstanced origDrawInstanced = (D3D11C_DrawInstanced)(*vTable)[21];
			D3D11C_DrawIndexedInstanced origDrawIndexedInstanced = (D3D11C_DrawIndexedInstanced)(*vTable)[20];

			cHookMgr.Hook(&(sDraw_Hook.nHookId), (LPVOID*)&(sDraw_Hook.fnDraw), origDraw, D3D11H_Draw);
			cHookMgr.Hook(&(sDrawAuto_Hook.nHookId), (LPVOID*)&(sDrawAuto_Hook.fnDrawAuto), origDrawAuto, D3D11H_DrawAuto);
			cHookMgr.Hook(&(sDrawIndexed_Hook.nHookId), (LPVOID*)&(sDrawIndexed_Hook.fnDrawIndexed), origDrawIndexed, D3D11H_DrawIndexed);
			cHookMgr.Hook(&(sDrawInstanced_Hook.nHookId), (LPVOID*)&(sDrawInstanced_Hook.fnDrawInstanced), origDrawInstanced, D3D11H_DrawInstanced);
			cHookMgr.Hook(&(sDrawIndexedInstanced_Hook.nHookId), (LPVOID*)&(sDrawIndexedInstanced_Hook.fnDrawIndexedInstanced), origDrawIndexedInstanced, D3D11H_DrawIndexedInstanced);

			gContext = *ppContext;

			LogInfo("Context COM hooked\n");
		}
	}
}

void hook(ID3D11Device** ppDevice) {
	if (ppDevice != NULL && *ppDevice != NULL) {
		LogInfo("Device Hook: %p\n", *ppDevice);
		if (!gl_hookedDevice) {
			gl_hookedDevice = true;
			DWORD_PTR*** vTable = (DWORD_PTR***)*ppDevice;
			D3D11_2D orig2D = (D3D11_2D)(*vTable)[6];
			D3D11_3D orig3D = (D3D11_3D)(*vTable)[7];
			D3D11_VS origVS = (D3D11_VS)(*vTable)[12];
			D3D11_PS origPS = (D3D11_PS)(*vTable)[15];
			D3D11_GS origGS = (D3D11_GS)(*vTable)[13];
			D3D11_HS origHS = (D3D11_HS)(*vTable)[16];
			D3D11_DS origDS = (D3D11_DS)(*vTable)[17];
			D3D11_CS origCS = (D3D11_CS)(*vTable)[18];

			cHookMgr.Hook(&(sCreateTexture2D_Hook.nHookId), (LPVOID*)&(sCreateTexture2D_Hook.fnCreateTexture2D), orig2D, D3D11_CreateTexture2D);
			cHookMgr.Hook(&(sCreateTexture3D_Hook.nHookId), (LPVOID*)&(sCreateTexture3D_Hook.fnCreateTexture3D), orig3D, D3D11_CreateTexture3D);

			cHookMgr.Hook(&(sCreateVertexShader_Hook.nHookId), (LPVOID*)&(sCreateVertexShader_Hook.fnCreateVertexShader), origVS, D3D11_CreateVertexShader);
			cHookMgr.Hook(&(sCreatePixelShader_Hook.nHookId), (LPVOID*)&(sCreatePixelShader_Hook.fnCreatePixelShader), origPS, D3D11_CreatePixelShader);
			cHookMgr.Hook(&(sCreateGeometryShader_Hook.nHookId), (LPVOID*)&(sCreateGeometryShader_Hook.fnCreateGeometryShader), origGS, D3D11_CreateGeometryShader);
			cHookMgr.Hook(&(sCreateHullShader_Hook.nHookId), (LPVOID*)&(sCreateHullShader_Hook.fnCreateHullShader), origHS, D3D11_CreateHullShader);
			cHookMgr.Hook(&(sCreateDomainShader_Hook.nHookId), (LPVOID*)&(sCreateDomainShader_Hook.fnCreateDomainShader), origDS, D3D11_CreateDomainShader);
			cHookMgr.Hook(&(sCreateComputeShader_Hook.nHookId), (LPVOID*)&(sCreateComputeShader_Hook.fnCreateComputeShader), origCS, D3D11_CreateComputeShader);
			LogInfo("Device COM hooked\n");

			HackedPresent(*ppDevice);
		}
		InitializeStereo(*ppDevice);
	}
}
#pragma endregion

#pragma region exports
// Exported function (faking d3d11.dll's export)
HRESULT WINAPI D3D11CreateDevice(
	_In_   IDXGIAdapter *pAdapter,
	_In_   D3D_DRIVER_TYPE DriverType,
	_In_   HMODULE Software,
	_In_   UINT Flags,
	_In_   const D3D_FEATURE_LEVEL *pFeatureLevels,
	_In_   UINT FeatureLevels,
	_In_   UINT SDKVersion,
	_Out_  ID3D11Device **ppDevice,
	_Out_  D3D_FEATURE_LEVEL *pFeatureLevel,
	_Out_  ID3D11DeviceContext **ppImmediateContext
	)
{
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d11.dll"
	
	// Hooking IDirect3D Object from Original Library
	typedef HRESULT (WINAPI* D3D11_Type)(
	IDXGIAdapter *pAdapter,
	D3D_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	const D3D_FEATURE_LEVEL *pFeatureLevels,
	UINT FeatureLevels,
	UINT SDKVersion,
	ID3D11Device **ppDevice,
	D3D_FEATURE_LEVEL *pFeatureLevel,
	ID3D11DeviceContext **ppImmediateContext
	);
	D3D11_Type D3D11CreateDevice_fn = (D3D11_Type) GetProcAddress( gl_hOriginalDll, "D3D11CreateDevice");
	HRESULT res = D3D11CreateDevice_fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, ppDevice, pFeatureLevel, ppImmediateContext);
	if (res == 0) {
		hook(ppDevice);
		hook(ppImmediateContext);
	}
	return res;
}
HRESULT WINAPI D3D11CreateDeviceAndSwapChain(
	_In_   IDXGIAdapter *pAdapter,
	_In_   D3D_DRIVER_TYPE DriverType,
	_In_   HMODULE Software,
	_In_   UINT Flags,
	_In_   const D3D_FEATURE_LEVEL *pFeatureLevels,
	_In_   UINT FeatureLevels,
	_In_   UINT SDKVersion,
	_In_   const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
	_Out_  IDXGISwapChain **ppSwapChain,
	_Out_  ID3D11Device **ppDevice,
	_Out_  D3D_FEATURE_LEVEL *pFeatureLevel,
	_Out_  ID3D11DeviceContext **ppImmediateContext
	)
{
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d11.dll"

	// Hooking IDirect3D Object from Original Library
	typedef HRESULT(WINAPI* D3D11_Type)(
		IDXGIAdapter *pAdapter,
		D3D_DRIVER_TYPE DriverType,
		HMODULE Software,
		INT Flags,
		const D3D_FEATURE_LEVEL *pFeatureLevels,
		UINT FeatureLevels,
		UINT SDKVersion,
		const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
		IDXGISwapChain **ppSwapChain,
		ID3D11Device **ppDevice,
		D3D_FEATURE_LEVEL *pFeatureLevel,
		ID3D11DeviceContext **ppImmediateContext
		);
	D3D11_Type D3D11CreateDeviceAndSwapChain_fn = (D3D11_Type)GetProcAddress(gl_hOriginalDll, "D3D11CreateDeviceAndSwapChain");
	HRESULT res = D3D11CreateDeviceAndSwapChain_fn(pAdapter, DriverType, Software, Flags, pFeatureLevels, FeatureLevels, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice, pFeatureLevel, ppImmediateContext);
	if (res == 0) {
		hook(ppDevice);
		hook(ppImmediateContext);
	}
	return res;
}
#pragma endregion

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

#pragma region INI
float ProcessParamTextureFilter(ParamOverride *override)
{
	D3D11_SHADER_RESOURCE_VIEW_DESC desc;
	ID3D11ShaderResourceView *view;
	ID3D11Resource *resource = NULL;
	TextureOverrideMap::iterator i;
	UINT64 hash = 0;
	float filter_index = 0;

	switch (override->shader_type) {
	case 'v':
		gContext->VSGetShaderResources(override->texture_slot, 1, &view);
		break;
	case 'h':
		gContext->HSGetShaderResources(override->texture_slot, 1, &view);
		break;
	case 'd':
		gContext->DSGetShaderResources(override->texture_slot, 1, &view);
		break;
	case 'g':
		gContext->GSGetShaderResources(override->texture_slot, 1, &view);
		break;
	case 'p':
		gContext->PSGetShaderResources(override->texture_slot, 1, &view);
		break;
	default:
		// Should not happen
		return filter_index;
	}
	if (!view)
		return filter_index;


	view->GetResource(&resource);
	if (!resource)
		goto out_release_view;

	view->GetDesc(&desc);

	switch (desc.ViewDimension) {
	case D3D11_SRV_DIMENSION_TEXTURE2D:
	case D3D11_SRV_DIMENSION_TEXTURE2DMS:
	case D3D11_SRV_DIMENSION_TEXTURE2DMSARRAY:
		hash = GetTexture2DHash((ID3D11Texture2D *)resource, false, NULL);
		break;
	case D3D11_SRV_DIMENSION_TEXTURE3D:
		hash = GetTexture3DHash((ID3D11Texture3D *)resource, false, NULL);
		break;
	}
	if (!hash)
		goto out_release_resource;

	i = mTextureOverrideMap.find(hash);
	if (i == mTextureOverrideMap.end())
		goto out_release_resource;

	filter_index = i->second.filter_index;

out_release_resource:
	resource->Release();
out_release_view:
	view->Release();
	return filter_index;
}

static void ParseParamOverride(const char *section, LPSTR ini,
	ParamOverride *override, char component, int index)
{
	char buf[MAX_PATH], param_name[8];
	int ret;

	_snprintf_s(param_name, 8, 8, "%lc%.0i", component, index);
	if (!GetPrivateProfileString(section, param_name, 0, buf, MAX_PATH, ini))
		return;

	// Try parsing setting as a float
	ret = scanf_s(buf, "%f", &override->val);
	if (ret != 0 && ret != EOF) {
		override->type = ParamOverrideType::VALUE;
		LogInfo("  %s=%#.2g\n", param_name, override->val);
		return;
	}

	// Try parsing setting as "<shader type>s-t<testure slot>" for texture filtering
	ret = scanf_s(buf, "%lcs-t%u", &override->shader_type, 1, &override->texture_slot);
	if (ret == 2 && override->texture_slot < D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT) {
		switch (override->shader_type) {
		case 'v': case 'h': case 'd': case 'g': case 'p':
			override->type = ParamOverrideType::TEXTURE;
			LogInfo("  %s=%lcs-t%u\n", param_name,
				override->shader_type,
				override->texture_slot);
			return;
		}
	}

	// Check special keywords
	if (!strcmp(buf, "rt_width")) override->type = ParamOverrideType::RT_WIDTH;
	if (!strcmp(buf, "rt_height")) override->type = ParamOverrideType::RT_HEIGHT;
	if (!strcmp(buf, "res_width")) override->type = ParamOverrideType::RES_WIDTH;
	if (!strcmp(buf, "res_height"))	override->type = ParamOverrideType::RES_HEIGHT;
	if (override->type != ParamOverrideType::INVALID)
		LogInfo("  %s=%s\n", param_name, buf);
}

void InitInstance()
{
	// Initialisation
	gl_hOriginalDll = NULL;

	char setting[MAX_PATH];
	char iniFile[MAX_PATH];
	char LOGfile[MAX_PATH];

	_getcwd(iniFile, MAX_PATH);
	_getcwd(LOGfile, MAX_PATH);
	_getcwd(cwd, MAX_PATH);
	strcat_s(iniFile, MAX_PATH, "\\d3dx.ini");

	// If specified in Debug section, wait for Attach to Debugger.
	bool waitfordebugger = GetPrivateProfileInt("Debug", "attach", 0, iniFile) > 0;
	if (waitfordebugger) {
		do {
			Sleep(250);
		} while (!IsDebuggerPresent());
	}

	gl_log = GetPrivateProfileInt("Logging", "calls", gl_log, iniFile) > 0;
	gl_hunt = GetPrivateProfileInt("Hunting", "hunting", gl_hunt, iniFile) > 0;
	gl_dump = GetPrivateProfileInt("Rendering", "export_binary", gl_dump, iniFile) > 0;
	gl_cache_shaders = GetPrivateProfileInt("Rendering", "cache_shaders", gl_cache_shaders, iniFile) > 0;

	if (gl_log) {
		strcat_s(LOGfile, MAX_PATH, "\\d3d11_log.txt");
		LogFile = _fsopen(LOGfile, "wb", _SH_DENYNO);
		setvbuf(LogFile, NULL, _IONBF, 0);
		LogInfo("Start Log:\n");
	}

	GetPrivateProfileString("Hunting", "next_pixelshader", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "next_pixelshader"));
	GetPrivateProfileString("Hunting", "previous_pixelshader", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "previous_pixelshader"));
	GetPrivateProfileString("Hunting", "mark_pixelshader", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "mark_pixelshader"));

	GetPrivateProfileString("Hunting", "next_vertexshader", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "next_vertexshader"));
	GetPrivateProfileString("Hunting", "previous_vertexshader", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "previous_vertexshader"));
	GetPrivateProfileString("Hunting", "mark_vertexshader", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "mark_vertexshader"));

	GetPrivateProfileString("Hunting", "reload_fixes", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "reload_fixes"));

	GetPrivateProfileString("Hunting", "toggle_hunting", 0, setting, MAX_PATH, iniFile);
	hBHs.push_back(new HuntButtonHandler(createButton(setting), "toggle_hunting"));

	// Read in any constants defined in the ini, for use as shader parameters
	// Any result of the default FLT_MAX means the parameter is not in use.
	// stof will crash if passed FLT_MAX, hence the extra check.
	// We use FLT_MAX instead of the more logical INFINITY, because Microsoft *always* generates 
	// warnings, even for simple comparisons. And NaN comparisons are similarly broken.
	LogInfo("[Constants]\n");
	for (int i = 0; i < INI_PARAMS_SIZE; i++) {
		char buf[8];
		iniParams[i].x = FLT_MAX;
		iniParams[i].y = FLT_MAX;
		iniParams[i].z = FLT_MAX;
		iniParams[i].w = FLT_MAX;
		_snprintf_s(buf, 8, "x%.0i", i);
		if (GetPrivateProfileString("Constants", buf, "FLT_MAX", setting, MAX_PATH, iniFile))
		{
			if (strcmp(setting, "FLT_MAX") != 0) {
				iniParams[i].x = stof(setting);
				LogInfo("  %s=%#.2g\n", buf, iniParams[i].x);
			}
		}
		_snprintf_s(buf, 8, "y%.0i", i);
		if (GetPrivateProfileString("Constants", buf, "FLT_MAX", setting, MAX_PATH, iniFile))
		{
			if (strcmp(setting, "FLT_MAX") != 0) {
				iniParams[i].y = stof(setting);
				LogInfo("  %s=%#.2g\n", buf, iniParams[i].y);
			}
		}
		_snprintf_s(buf, 8, "z%.0i", i);
		if (GetPrivateProfileString("Constants", buf, "FLT_MAX", setting, MAX_PATH, iniFile))
		{
			if (strcmp(setting, "FLT_MAX") != 0) {
				iniParams[i].z = stof(setting);
				LogInfo("  %s=%#.2g\n", buf, iniParams[i].z);
			}
		}
		_snprintf_s(buf, 8, "w%.0i", i);
		if (GetPrivateProfileString("Constants", buf, "FLT_MAX", setting, MAX_PATH, iniFile))
		{
			if (strcmp(setting, "FLT_MAX") != 0) {
				iniParams[i].w = stof(setting);
				LogInfo("  %s=%#.2g\n", buf, iniParams[i].w);
			}
		}
	}
	if (GetPrivateProfileString("Device", "get_resolution_from", 0, setting, MAX_PATH, iniFile)) {
		if (_stricmp(setting, "swap_chain") == 0)
			gResolutionInfo.from = GetResolutionFrom::SWAP_CHAIN;
		if (_stricmp(setting, "depth_stencil") == 0)
			gResolutionInfo.from = GetResolutionFrom::DEPTH_STENCIL;
	}

	KeyType type;
	char key[MAX_PATH];
	char buf[MAX_PATH];

	vector<string> Keys;
	vector<string> Shaders;
	vector<string> Textures;
	char sectionNames[10000];
	GetPrivateProfileSectionNames(sectionNames, 10000, iniFile);
	size_t position = 0;
	size_t length = strlen(&sectionNames[position]);
	while (length != 0) {
		if (strncmp(&sectionNames[position], "Key", 3) == 0)
			Keys.push_back(&sectionNames[position]);
		if (strncmp(&sectionNames[position], "ShaderOverride", 14) == 0)
			Shaders.push_back(&sectionNames[position]);
		if (strncmp(&sectionNames[position], "TextureOverride", 15) == 0)
			Textures.push_back(&sectionNames[position]);
		position += length + 1;
		length = strlen(&sectionNames[position]);
	}

	mShaderOverrideMap.clear();
	for (size_t i = 0; i < Shaders.size(); i++) {
		UINT64 hash, hash2;
		int j;
		ShaderOverride *override;
		const char *id = Shaders[i].c_str();

		LogInfo("[%s]\n", id);

		if (!GetPrivateProfileString(id, "Hash", 0, setting, MAX_PATH, iniFile))
			break;
		sscanf_s(setting, "%16llx", &hash);
		LogInfo("  Hash=%16llx\n", hash);

		if (mShaderOverrideMap.count(hash)) {
			LogInfo("  WARNING: Duplicate ShaderOverride hash: %16llx\n", hash);
			BeepFailure2();
		}
		override = &mShaderOverrideMap[hash];

		if (GetPrivateProfileString(id, "Separation", 0, setting, MAX_PATH, iniFile))
		{
			sscanf_s(setting, "%e", &override->separation);
			LogInfo("  Separation=%f\n", override->separation);
		}
		if (GetPrivateProfileString(id, "Convergence", 0, setting, MAX_PATH, iniFile))
		{
			sscanf_s(setting, "%e", &override->convergence);
			LogInfo("  Convergence=%f\n", override->convergence);
		}
		if (GetPrivateProfileString(id, "Handling", 0, setting, MAX_PATH, iniFile)) {
			if (!strcmp(setting, "skip")) {
				override->skip = true;
				LogInfo("  Handling=skip\n");
			}
			else {
				LogInfo("  WARNING: Unknown handling type \"%s\"\n", setting);
				BeepFailure2();
			}
		}
		if (GetPrivateProfileString(id, "depth_filter", 0, setting, MAX_PATH, iniFile)) {
			if (!strcmp(setting, "depth_active"))
				override->depth_filter = DepthBufferFilter::DEPTH_ACTIVE;
			if (!strcmp(setting, "depth_inactive"))
				override->depth_filter = DepthBufferFilter::DEPTH_INACTIVE;
		}

		if (GetPrivateProfileString(id, "partner", 0, setting, MAX_PATH, iniFile)) {
			sscanf_s(setting, "%16llx", &override->partner_hash);
			LogInfo("  partner=%16llx\n", override->partner_hash);
		}

		if (GetPrivateProfileString(id, "Iteration", 0, setting, MAX_PATH, iniFile))
		{
			// XXX: This differs from the TextureOverride
			// iterations, in that there can only be one iteration
			// here - not sure why.
			int iteration;
			override->iterations.clear();
			override->iterations.push_back(0);
			sscanf_s(setting, "%d", &iteration);
			LogInfo("  Iteration=%d\n", iteration);
			override->iterations.push_back(iteration);
		}

		if (GetPrivateProfileString(id, "IndexBufferFilter", 0, setting, MAX_PATH, iniFile))
		{
			sscanf_s(setting, "%16llx", &hash2);
			LogInfo("  IndexBufferFilter=%16llx\n", hash2);
			override->indexBufferFilter.push_back(hash2);
		}

		override->fake_o0 = GetPrivateProfileInt(id, "fake_o0", 0, iniFile) == 1;
		if (override->fake_o0)
			LogInfo("  fake_o0=1\n");

		override->depth_input = GetPrivateProfileInt(id, "depth_input", 0, iniFile);
		if (override->depth_input)
			LogInfo("  depth_input=%d\n", override->depth_input);
		if (override->depth_input >= D3D11_COMMONSHADER_INPUT_RESOURCE_SLOT_COUNT) {
			LogInfo("  depth_input out of range!\n");
			override->depth_input = 0;
			BeepFailure2();
		}

		for (j = 0; j < INI_PARAMS_SIZE; j++) {
			ParseParamOverride(id, iniFile, &override->x[j], L'x', j);
			ParseParamOverride(id, iniFile, &override->y[j], L'y', j);
			ParseParamOverride(id, iniFile, &override->z[j], L'z', j);
			ParseParamOverride(id, iniFile, &override->w[j], L'w', j);
		}
	}

	mTextureOverrideMap.clear();
	for (size_t i = 0; i < Textures.size(); i++) {
		UINT64 hash;
		TextureOverride *override;
		const char* id = Shaders[i].c_str();
		LogInfo("[%s]\n", id);

		if (!GetPrivateProfileString(id, "Hash", 0, setting, MAX_PATH, iniFile))
			break;
		sscanf_s(setting, "%16llx", &hash);
		LogInfo("  Hash=%16llx\n", hash);

		if (mTextureOverrideMap.count(hash)) {
			LogInfo("  WARNING: Duplicate TextureOverride hash: %16llx\n", hash);
			BeepFailure2();
		}
		override = &mTextureOverrideMap[hash];

		int stereoMode = GetPrivateProfileInt(id, "StereoMode", -1, iniFile);
		if (stereoMode >= 0)
		{
			override->stereoMode = stereoMode;
			LogInfo("  StereoMode=%d\n", stereoMode);
		}
		int texFormat = GetPrivateProfileInt(id, "Format", -1, iniFile);
		if (texFormat >= 0)
		{
			override->format = texFormat;
			LogInfo("  Format=%d\n", texFormat);
		}
		if (GetPrivateProfileString(id, "Iteration", 0, setting, MAX_PATH, iniFile))
		{
			// TODO: This supports more iterations than the
			// ShaderOverride iteration parameter, and it's not
			// clear why there is a difference. This seems like the
			// better way, but should change it to use my list
			// parsing code rather than hard coding a maximum of 10
			// supported iterations.
			override->iterations.clear();
			override->iterations.push_back(0);
			int id[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			scanf_s(setting, L"%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", id + 0, id + 1, id + 2, id + 3, id + 4, id + 5, id + 6, id + 7, id + 8, id + 9);
			for (int j = 0; j < 10; ++j)
			{
				if (id[j] <= 0) break;
				override->iterations.push_back(id[j]);
				LogInfo("  Iteration=%d\n", id[j]);
			}
		}

		if (GetPrivateProfileString(id, "filter_index", 0, setting, MAX_PATH, iniFile)) {
			sscanf_s(setting, "%f", &override->filter_index);
			LogInfo("  filter_index=%f\n", override->filter_index);
		}

		override->expand_region_copy = GetPrivateProfileInt(id, "expand_region_copy", 0, iniFile) == 1;
		override->deny_cpu_read = GetPrivateProfileInt(id, "deny_cpu_read", 0, iniFile) == 1;
	}

	for (size_t i = 0; i < Keys.size(); i++) {
		const char* id = Keys[i].c_str();
		if (!GetPrivateProfileString(id, "Key", 0, key, MAX_PATH, iniFile))
			continue;

		type = KeyType::Activate;

		if (GetPrivateProfileString(id, "type", 0, buf, MAX_PATH, iniFile)) {
			if (!_stricmp(buf, "hold")) {
				type = KeyType::Hold;
			}
			else if (!_stricmp(buf, "toggle")) {
				type = KeyType::Toggle;
			}
			else if (!_stricmp(buf, "cycle")) {
				type = KeyType::Cycle;
			}
		}

		TransitionType tType = TransitionType::Linear;
		if (GetPrivateProfileString(id, "transition_type", 0, buf, MAX_PATH, iniFile)) {
			if (!_stricmp(buf, "cosine"))
				tType = TransitionType::Cosine;
		}

		TransitionType rtType = TransitionType::Linear;
		if (GetPrivateProfileString(id, "release_transition_type", 0, buf, MAX_PATH, iniFile)) {
			if (!_stricmp(buf, "cosine"))
				rtType = TransitionType::Cosine;
		}

		vector<string> fs = { "", "", "", "", "", "", "", "", "", "" };
		int varFlags = 0;

		if (GetPrivateProfileString(id, "x", 0, buf, MAX_PATH, iniFile)) {
			fs[0] = buf;
			varFlags |= 1;
		}
		if (GetPrivateProfileString(id, "y", 0, buf, MAX_PATH, iniFile)) {
			fs[1] = buf;
			varFlags |= 2;
		}
		if (GetPrivateProfileString(id, "z", 0, buf, MAX_PATH, iniFile)) {
			fs[2] = buf;
			varFlags |= 4;
		}
		if (GetPrivateProfileString(id, "w", 0, buf, MAX_PATH, iniFile)) {
			fs[3] = buf;
			varFlags |= 8;
		}
		if (GetPrivateProfileString(id, "convergence", 0, buf, MAX_PATH, iniFile)) {
			fs[4] = buf;
			varFlags |= 16;
		}
		if (GetPrivateProfileString(id, "separation", 0, buf, MAX_PATH, iniFile)) {
			fs[5] = buf;
			varFlags |= 32;
		}
		if (GetPrivateProfileString(id, "delay", 0, buf, MAX_PATH, iniFile)) {
			fs[6] = buf;
			varFlags |= 64;
		}
		if (GetPrivateProfileString(id, "transition", 0, buf, MAX_PATH, iniFile)) {
			fs[7] = buf;
			varFlags |= 128;
		}
		if (GetPrivateProfileString(id, "release_delay", 0, buf, MAX_PATH, iniFile)) {
			fs[8] = buf;
			varFlags |= 256;
		}
		if (GetPrivateProfileString(id, "release_transition", 0, buf, MAX_PATH, iniFile)) {
			fs[9] = buf;
			varFlags |= 512;
		}
		BHs.push_back(new ButtonHandler(createButton(key), type, varFlags, fs, tType, rtType));
	}

	InitializeCriticalSection(&gl_CS);

	gStereoTexMgr = new nv::stereo::ParamTextureManagerD3D11;

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
}
#pragma endregion

void LoadOriginalDll(void)
{
	if (!gl_hOriginalDll) gl_hOriginalDll = Hooked_LoadLibraryExW(L"original_d3d11.dll", NULL, 0);
}

void ExitInstance() 
{    
	if (gl_hOriginalDll)
	{
		::FreeLibrary(gl_hOriginalDll);
	    gl_hOriginalDll = NULL;  
	}
}

extern "C" NvAPI_Status __cdecl nvapi_QueryInterface(unsigned int offset);

void NvAPIOverride() {
	// One shot, override custom settings.
	NvAPI_Status ret = nvapi_QueryInterface(0xb03bb03b);
	if (ret != 0xeecc34ab)
		LogInfo("  overriding NVAPI wrapper failed. \n");
}