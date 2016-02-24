// proxydll.cpp
#include "proxy10dll.h"
#include "resource.h"
#include "Nektra\NktHookLib.h"

// global variables
#pragma data_seg (".d3d10_shared")
HINSTANCE           gl_hOriginalDll;
HINSTANCE           gl_hThisInstance;
bool				gl_hookedDevice = false;
bool				gl_dump = true;
bool				gl_log = true;
FILE*				LogFile = NULL;
char				cwd[MAX_PATH];
CRITICAL_SECTION	gl_CS;
#pragma data_seg ()

CNktHookLib cHookMgr;

BOOL WINAPI DllMain(
	_In_  HINSTANCE hinstDLL,
	_In_  DWORD fdwReason,
	_In_  LPVOID lpvReserved)
{
	bool result = true;

	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		gl_hThisInstance = hinstDLL;
		ShowStartupScreen();
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

HRESULT STDMETHODCALLTYPE D3D10_CreateVertexShader(
	ID3D10Device * This,
	__in  const void *pShaderBytecode,
	__in  SIZE_T BytecodeLength,
	__out_opt  ID3D10VertexShader **ppVertexShader) {
	EnterCriticalSection(&gl_CS);
	FILE* f = NULL;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	char buffer[80];
	char path[MAX_PATH];
	
	if (gl_dump) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-vs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
	}
	LogInfo("Create VertexShader: %016llX\n", _crc);
	HRESULT res = sCreateVertexShader_Hook.fnCreateVertexshader(This, pShaderBytecode, BytecodeLength, ppVertexShader);
	LeaveCriticalSection(&gl_CS);
	return res;
}

HRESULT STDMETHODCALLTYPE D3D10_CreatePixelShader(
	ID3D10Device * This,
	__in  const void *pShaderBytecode,
	__in  SIZE_T BytecodeLength,
	__out_opt  ID3D10PixelShader **ppPixelShader) {
	EnterCriticalSection(&gl_CS);
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	char buffer[80];
	char path[MAX_PATH];

	if (gl_dump) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-ps.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
	}
	LogInfo("Create PixelShader: %016llX\n", _crc);
	HRESULT res = sCreatePixelShader_Hook.fnCreatePixelshader(This, pShaderBytecode, BytecodeLength, ppPixelShader);
	LeaveCriticalSection(&gl_CS);
	return res;
}

HRESULT STDMETHODCALLTYPE D3D10_CreateGeometryShader(
	ID3D10Device * This,
	__in  const void *pShaderBytecode,
	__in  SIZE_T BytecodeLength,
	__out_opt  ID3D10GeometryShader **ppGeometryShader) {
	EnterCriticalSection(&gl_CS);
	FILE* f;
	UINT64 _crc = fnv_64_buf(pShaderBytecode, BytecodeLength);
	char buffer[80];
	char path[MAX_PATH];

	if (gl_dump) {
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, "\\ShaderCache");
		CreateDirectory(path, NULL);

		sprintf_s(buffer, 80, "\\ShaderCache\\%016llX-gs.bin", _crc);
		path[0] = 0;
		strcat_s(path, MAX_PATH, cwd);
		strcat_s(path, MAX_PATH, buffer);

		fopen_s(&f, path, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);
	}
	LogInfo("Create GeometryShader: %016llX\n", _crc);
	HRESULT res = sCreateGeometryShader_Hook.fnCreateGeometryShader(This, pShaderBytecode, BytecodeLength, ppGeometryShader);
	LeaveCriticalSection(&gl_CS);
	return res;
}

void hook(ID3D10Device** ppDevice) {
	if (ppDevice != NULL) {
		LogInfo("Hook: %p", *ppDevice);
		if (*ppDevice != NULL && !gl_hookedDevice) {
			gl_hookedDevice = true;
			DWORD*** vTable = (DWORD***)*ppDevice;
			D3D10_VS origVS = (D3D10_VS)(*vTable)[79];
			D3D10_PS origPS = (D3D10_PS)(*vTable)[82];
			D3D10_GS origGS = (D3D10_GS)(*vTable)[80];

			cHookMgr.Hook(&(sCreateVertexShader_Hook.nHookId), (LPVOID*)&(sCreateVertexShader_Hook.fnCreateVertexshader), origVS, D3D10_CreateVertexShader);
			cHookMgr.Hook(&(sCreatePixelShader_Hook.nHookId), (LPVOID*)&(sCreatePixelShader_Hook.fnCreatePixelshader), origPS, D3D10_CreatePixelShader);
			cHookMgr.Hook(&(sCreateGeometryShader_Hook.nHookId), (LPVOID*)&(sCreateGeometryShader_Hook.fnCreateGeometryShader), origGS, D3D10_CreateGeometryShader);
		}
	}
}

// Exported function (faking d3d10.dll's export)
HRESULT WINAPI D3D10CreateDevice(
	_In_   IDXGIAdapter *pAdapter,
	_In_   D3D10_DRIVER_TYPE DriverType,
	_In_   HMODULE Software,
	_In_   UINT Flags,
	_In_   UINT SDKVersion,
	_Out_  ID3D10Device **ppDevice
	)
{
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d10.dll"
	
	// Hooking IDirect3D Object from Original Library
	typedef HRESULT (WINAPI* D3D10_Type)(
	IDXGIAdapter *pAdapter,
	D3D10_DRIVER_TYPE DriverType,
	HMODULE Software,
	UINT Flags,
	UINT SDKVersion,
	ID3D10Device **ppDevice
	);
	D3D10_Type D3D10CreateDevice_fn = (D3D10_Type) GetProcAddress( gl_hOriginalDll, "D3D10CreateDevice");
    
    HRESULT res = D3D10CreateDevice_fn(pAdapter, DriverType, Software, Flags, SDKVersion, ppDevice);
	hook(ppDevice);
	return res;
}
HRESULT WINAPI D3D10CreateDeviceAndSwapChain(
	_In_   IDXGIAdapter *pAdapter,
	_In_   D3D10_DRIVER_TYPE DriverType,
	_In_   HMODULE Software,
	_In_   UINT Flags,
	_In_   UINT SDKVersion,
	_In_   DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
	_Out_  IDXGISwapChain **ppSwapChain,
	_Out_  ID3D10Device **ppDevice
	)
{
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d10.dll"

	// Hooking IDirect3D Object from Original Library
	typedef HRESULT(WINAPI* D3D10_Type)(
		IDXGIAdapter *pAdapter,
		D3D10_DRIVER_TYPE DriverType,
		HMODULE Software,
		UINT Flags,
		UINT SDKVersion,
		const DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
		IDXGISwapChain **ppSwapChain,
		ID3D10Device **ppDevice
		);
	D3D10_Type D3D10CreateDeviceAndSwapChain_fn = (D3D10_Type)GetProcAddress(gl_hOriginalDll, "D3D10CreateDeviceAndSwapChain");
	HRESULT res = D3D10CreateDeviceAndSwapChain_fn(pAdapter, DriverType, Software, Flags, SDKVersion, pSwapChainDesc, ppSwapChain, ppDevice);
	hook(ppDevice);
	return res;
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

void InitInstance() 
{
	// Initialisation
	gl_hOriginalDll = NULL;
	gl_hThisInstance = NULL;

	_getcwd(cwd, MAX_PATH);
	if (gl_log) {
		char LOGfile[MAX_PATH];
		_getcwd(LOGfile, MAX_PATH);
		strcat_s(LOGfile, MAX_PATH, "\\d3d10_log.txt");
		LogFile = _fsopen(LOGfile, "wb", _SH_DENYNO);
		setvbuf(LogFile, NULL, _IONBF, 0);
		LogInfo("Start Log:\n");
	}
	InitializeCriticalSection(&gl_CS);
}

void LoadOriginalDll(void)
{
    char buffer[MAX_PATH];
    
	::GetSystemDirectory(buffer,MAX_PATH);
	strcat_s(buffer, MAX_PATH, "\\d3d10.dll");

	if (!gl_hOriginalDll) gl_hOriginalDll = ::LoadLibrary(buffer);
}

void ExitInstance() 
{    
	if (gl_hOriginalDll)
	{
		::FreeLibrary(gl_hOriginalDll);
	    gl_hOriginalDll = NULL;  
	}
}

