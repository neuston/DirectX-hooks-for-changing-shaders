// proxydll.cpp
#include "stdafx.h"
#include "proxydll.h"
#include "..\log.h"
#include "..\vkeys.h"
#include "resource.h"
#include "..\Nektra\NktHookLib.h"
#define NO_STEREO_D3D11
#define NO_STEREO_D3D10
#include "..\nvstereo.h"

// global variables
#pragma data_seg (".d3d9_shared")
HINSTANCE           gl_hOriginalDll;
HINSTANCE           gl_hThisInstance;
D3D9_Create			gl_origCreate;
D3D9_VS				gl_origVS;
D3D9_PS				gl_origPS;
D3D9_VSSS			gl_origVSSS;
D3D9_PSSS			gl_origPSSS;
D3D9_P				gl_origPresent;
D3D9_DP				gl_origDP;
D3D9_DIP			gl_origDIP;
D3D9_DPUP			gl_origDPUP;
D3D9_DIPUP			gl_origDIPUP;
bool				gl_hooked = false;
bool				gl_hooked2 = false;
bool				gl_dump = false;
bool				gl_patch = true;
bool				gl_log = false;
bool				gl_hunt = false;
FILE*				LogFile = NULL;
char				cwd[MAX_PATH];
nv::stereo::ParamTextureManagerD3D9 *gStereoTexMgr = NULL;
IDirect3DTexture9 *	gStereoTexture;
bool gInitGfx = false;
#pragma data_seg ()

CNktHookLib cHookMgr;

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

BOOL APIENTRY DllMain( HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	// to avoid compiler lvl4 warnings 
    LPVOID lpDummy = lpReserved;
    lpDummy = NULL;

    switch (ul_reason_for_call)
	{
	    case DLL_PROCESS_ATTACH:
			gl_hThisInstance = (HINSTANCE)hModule;
			ShowStartupScreen();
			InitInstance();
			break;
	    case DLL_PROCESS_DETACH: ExitInstance(); break;
        
        case DLL_THREAD_ATTACH:  break;
	    case DLL_THREAD_DETACH:  break;
	}
    return TRUE;
}

map <uint32_t, vector<byte>*> origShaderData;

map<IDirect3DVertexShader9*, uint32_t> ShaderMapVS;
HRESULT STDMETHODCALLTYPE D3D9_CreateVS(IDirect3DDevice9 * This, CONST DWORD* pFunction, IDirect3DVertexShader9** ppShader) {
	int i;
	for (i = 0; pFunction[i] != 0xFFFF; i++) {}
	i++;
	LPD3DXBUFFER pDisassembly = NULL;
	HRESULT dRes = D3DXDisassembleShader(pFunction, FALSE, NULL, &pDisassembly);
	LPVOID pShaderBytecode = pDisassembly->GetBufferPointer();
	DWORD BytecodeLength = pDisassembly->GetBufferSize();
	char buffer[80];
	FILE* f;
	uint32_t _crc = crc32_fast(pFunction, 4 * i, 0);

	LogInfo("Create VS: %08X\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dump) {
		sprintf_s(buffer, 80, "Dumps\\AllShaders\\VertexShaders\\%08X.txt", _crc);
		fopen_s(&f, buffer, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);

		sprintf_s(buffer, 80, "Dumps\\AllShaders\\VertexShaders\\%08X.bin", _crc);
		fopen_s(&f, buffer, "wb");
		fwrite(pFunction, 4, i, f);
		fclose(f);
	}
	if (gl_patch) {
		sprintf_s(buffer, 80, "shaderoverride\\vertexshaders\\%08X.txt", _crc);
		fopen_s(&f, buffer, "rb");
		if (f != NULL) {
			char* shader = new char[BytecodeLength * 2];
			size_t size = fread(shader, 1, BytecodeLength * 2, f);
			fclose(f);
			LPD3DXBUFFER pAssembly;
			D3DXAssembleShader(shader, size, NULL, NULL, 0, &pAssembly, NULL);
			if (pAssembly != NULL)  {
				HRESULT hr = sCreateVS_Hook.fnCreateVS(This, (CONST DWORD*)pAssembly->GetBufferPointer(), ppShader);
				ShaderMapVS[*ppShader] = _crc;
				return hr;
			}
		}
	}
	HRESULT hr = sCreateVS_Hook.fnCreateVS(This, pFunction, ppShader);
	ShaderMapVS[*ppShader] = _crc;
	return hr;
}

map<IDirect3DPixelShader9*, uint32_t> ShaderMapPS;
HRESULT STDMETHODCALLTYPE D3D9_CreatePS(IDirect3DDevice9 * This, CONST DWORD* pFunction, IDirect3DPixelShader9** ppShader) {
	int i;
	for (i = 0; pFunction[i] != 0xFFFF; i++) {}
	i++;
	LPD3DXBUFFER pDisassembly = NULL;
	HRESULT dRes = D3DXDisassembleShader(pFunction, FALSE, NULL, &pDisassembly);
	LPVOID pShaderBytecode = pDisassembly->GetBufferPointer();
	DWORD BytecodeLength = pDisassembly->GetBufferSize();
	char buffer[80];
	FILE* f;
	uint32_t _crc = crc32_fast(pFunction, 4 * i, 0);

	LogInfo("Create PS: %08X\n", _crc);

	vector<byte> *v = new vector<byte>(BytecodeLength);
	copy((byte*)pShaderBytecode, (byte*)pShaderBytecode + BytecodeLength, v->begin());
	origShaderData[_crc] = v;

	if (gl_dump) {
		sprintf_s(buffer, 80, "Dumps\\AllShaders\\PixelShaders\\%08X.txt", _crc);
		fopen_s(&f, buffer, "wb");
		fwrite(pShaderBytecode, 1, BytecodeLength, f);
		fclose(f);

		sprintf_s(buffer, 80, "Dumps\\AllShaders\\PixelShaders\\%08X.bin", _crc);
		fopen_s(&f, buffer, "wb");
		fwrite(pFunction, 4, i, f);
		fclose(f);
	}
	if (gl_patch) {
		sprintf_s(buffer, 80, "shaderoverride\\pixelshaders\\%08X.txt", _crc);
		fopen_s(&f, buffer, "rb");
		if (f != NULL) {
			char* shader = new char[BytecodeLength * 2];
			size_t size = fread(shader, 1, BytecodeLength * 2, f);
			fclose(f);
			LPD3DXBUFFER pAssembly;
			D3DXAssembleShader(shader, size, NULL, NULL, 0, &pAssembly, NULL);
			if (pAssembly != NULL) {
				HRESULT hr = sCreatePS_Hook.fnCreatePS(This, (CONST DWORD*)pAssembly->GetBufferPointer(), ppShader);
				ShaderMapPS[*ppShader] = _crc;
				return hr;
			}
		}
	}
	HRESULT hr = sCreatePS_Hook.fnCreatePS(This, pFunction, ppShader);
	ShaderMapPS[*ppShader] = _crc;
	return hr;
}

map<uint32_t, IDirect3DVertexShader9*> RunningVS;
uint32_t currentVS = 0xFFFFFFFF;
HRESULT STDMETHODCALLTYPE D3D9_VSSetShader(IDirect3DDevice9 * This, IDirect3DVertexShader9* pShader) {
	if (ShaderMapVS.count(pShader)) {
		uint32_t _crc = ShaderMapVS[pShader];
		LogInfo("VS: %08X\n", _crc);
		RunningVS[_crc] = pShader;
		currentVS = _crc;
	}
	HRESULT hr = sVSSS_Hook.fnVSSS(This, pShader);
	This->SetTexture(D3DVERTEXTEXTURESAMPLER0, gStereoTexture);
	return hr;
}

map<uint32_t, IDirect3DPixelShader9*> RunningPS;
uint32_t currentPS = 0xFFFFFFFF;
HRESULT STDMETHODCALLTYPE D3D9_PSSetShader(IDirect3DDevice9 * This, IDirect3DPixelShader9* pShader) {
	if (ShaderMapPS.count(pShader)) {
		uint32_t _crc = ShaderMapPS[pShader];
		LogInfo("PS: %08X\n", _crc);
		RunningPS[_crc] = pShader;
		currentPS = _crc;
	}
	HRESULT hr = sPSSS_Hook.fnPSSS(This, pShader);
	This->SetTexture(0, gStereoTexture);
	return hr;
}

HRESULT CreateStereoParamTexture(IDirect3DDevice9* d3d9)
{
	// This function creates a texture that is suitable to be stereoized by the driver.
	// Note that the parameters primarily come from nvstereo.h
	using nv::stereo::ParamTextureManagerD3D9;
	
	d3d9->CreateTexture(ParamTextureManagerD3D9::Parms::StereoTexWidth,
		ParamTextureManagerD3D9::Parms::StereoTexHeight, 1, D3DUSAGE_DYNAMIC,
		ParamTextureManagerD3D9::Parms::StereoTexFormat, D3DPOOL_DEFAULT, &gStereoTexture, NULL);
	return S_OK;
}

map<uint32_t, IDirect3DPixelShader9*> PresentPS;
map<uint32_t, IDirect3DVertexShader9*> PresentVS;
uint32_t PS_hash = 0;
uint32_t VS_hash = 0;
uint32_t test = 0;
uint32_t limit = 2;
HRESULT STDMETHODCALLTYPE D3D9_Present(IDirect3DDevice9 * This, CONST RECT* pSourceRect, CONST RECT* pDestRect, HWND hDestWindowOverride, CONST RGNDATA* pDirtyRegion) {
	if (test < limit)
		test++;
	if (test == limit) {
		test++;
		CreateStereoParamTexture(This);
	}
	if (test > limit)
		gStereoTexMgr->UpdateStereoTexture(This, gStereoTexture, false);
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
	return sPresent_Hook.fnPresent(This, pSourceRect, pDestRect, hDestWindowOverride, pDirtyRegion);
}

bool beforeDraw() {
	return currentPS == PS_hash || currentVS == VS_hash;
}

HRESULT STDMETHODCALLTYPE D3D9_DrawPrimitive(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, UINT StartVertex, UINT PrimitiveCount) {
	if (beforeDraw())
		return S_OK;
	else
		return sDrawPrimitive_Hook.fnDrawPrimitive(This, PrimitiveType, StartVertex, PrimitiveCount);
}

HRESULT STDMETHODCALLTYPE D3D9_DrawIndexedPrimitive(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, INT BaseVertexIndex, UINT MinVertexIndex, UINT NumVertices, UINT startIndex, UINT primCount) {
	if (beforeDraw())
		return S_OK;
	else
		return sDrawIndexedPrimitive_Hook.fnDrawIndexedPrimitive(This, PrimitiveType, BaseVertexIndex, MinVertexIndex, NumVertices, startIndex, primCount);
}

HRESULT STDMETHODCALLTYPE D3D9_DrawPrimitiveUP(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, UINT PrimitiveCount, CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride) {
	if (beforeDraw())
		return S_OK;
	else
		return sDrawPrimitiveUP_Hook.fnDrawPrimitiveUP(This, PrimitiveType, PrimitiveCount, pVertexStreamZeroData, VertexStreamZeroStride);
}

/*
HRESULT STDMETHODCALLTYPE D3D9_DrawIndexedPrimitiveUP(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, UINT MinVertexIndex, UINT NumVertices, UINT PrimitiveCount, CONST void* pIndexData, D3DFORMAT IndexDataFormat, CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride) {
	if (beforeDraw())
		return S_OK;
	else
		return sDrawIndexedPrimitiveUP_Hook.fnDrawIndexedPrimitiveUP(This, PrimitiveType, PrimitiveCount, NumVertices, PrimitiveCount, pIndexData, IndexDataFormat, pVertexStreamZeroData, VertexStreamZeroStride);
}
*/

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
button* createButton(string key) {
	return new keyboardMouseKey(key);
}

void HuntBeep() {
	Beep(440, 200);
}

class HuntButtonHandler {
public:
	HuntButtonHandler(button* b, string command) {
		Button = b;
		Command = command;
	}
	void Handle() {
		buttonPress status = Button->buttonCheck();
		FILE* f;

		if (status == buttonPress::Down && gl_hunt) {
			if (PresentPS.size() > 0) {
				if (!strcmp(Command.c_str(), "next_pixelshader")) {
					if (PS_hash == 0) {
						PS_hash = PresentPS.begin()->first;
					} else {
						auto it = PresentPS.find(PS_hash);
						if (it != PresentPS.end()) {
							int i = 1;
							for (auto it2 = PresentPS.begin(); it2 != it; it2++)
								i++;
							if (i == PresentPS.size()) {
								PS_hash = 0;
								HuntBeep();
							} else {
								it++;
								PS_hash = it->first;
							}
						} else {
							PS_hash = 0;
							for (auto it = PresentPS.begin(); it != PresentPS.end(); it++)
								if (it->first < PS_hash)
									PS_hash = it->first;
							if (PS_hash == 0)
								HuntBeep();
						}
					}
				}
				if (!strcmp(Command.c_str(), "previous_pixelshader")) {
					if (PS_hash == 0) {
						PS_hash = PresentPS.rbegin()->first;
					} else {
						auto it = PresentPS.find(PS_hash);
						if (it != PresentPS.end()) {
							int i = 1;
							for (auto it2 = PresentPS.begin(); it2 != it; it2++)
								i++;
							if (i == 1) {
								PS_hash = 0;
								HuntBeep();
							} else {
								it--;
								PS_hash = it->first;
							}
						} else {
							PS_hash = 0;
							for (auto it = PresentPS.rbegin(); it != PresentPS.rend(); it++)
								if (it->first > PS_hash)
									PS_hash = it->first;
							if (PS_hash == 0)
								HuntBeep();
						}
					}
				}
				if (!strcmp(Command.c_str(), "mark_pixelshader")) {
					CreateDirectory("Dumps", NULL);
					CreateDirectory("Dumps\\SingleShaders", NULL);
					CreateDirectory("Dumps\\SingleShaders\\PixelShader", NULL);

					auto _crc = PS_hash;
					char buffer[80];
					sprintf_s(buffer, 80, "Dumps\\SingleShaders\\PixelShader\\%08X.txt", _crc);
					fopen_s(&f, buffer, "wb");

					vector<byte> * v = origShaderData[_crc];
					fwrite(v->data(), 1, v->size(), f);
					fclose(f);
				}
			}
			if (PresentVS.size() > 0) {
				if (!strcmp(Command.c_str(), "next_vertexshader")) {
					if (VS_hash == 0) {
						VS_hash = PresentVS.begin()->first;
					} else {
						auto it = PresentVS.find(VS_hash);
						if (it != PresentVS.end()) {
							int i = 1;
							for (auto it2 = PresentVS.begin(); it2 != it; it2++)
								i++;
							if (i == PresentVS.size()) {
								VS_hash = 0;
								HuntBeep();
							} else {
								it++;
								VS_hash = it->first;
							}
						} else {
							VS_hash = 0;
							for (auto it = PresentVS.begin(); it != PresentVS.end(); it++)
								if (it->first < VS_hash)
									VS_hash = it->first;
							if (VS_hash == 0)
								HuntBeep();
						}
					}
				}
				if (!strcmp(Command.c_str(), "previous_vertexshader")) {
					if (VS_hash == 0) {
						VS_hash = PresentVS.rbegin()->first;
					} else {
						auto it = PresentVS.find(VS_hash);
						if (it != PresentVS.end()) {
							int i = 1;
							for (auto it2 = PresentVS.begin(); it2 != it; it2++)
								i++;
							if (i == 1) {
								VS_hash = 0;
								HuntBeep();
							} else {
								it--;
								VS_hash = it->first;
							}
						} else {
							VS_hash = 0;
							for (auto it = PresentVS.rbegin(); it != PresentVS.rend(); it++)
								if (it->first > VS_hash)
									VS_hash = it->first;
							if (VS_hash == 0)
								HuntBeep();
						}
					}
				}
				if (!strcmp(Command.c_str(), "mark_vertexshader")) {
					CreateDirectory("Dumps", NULL);
					CreateDirectory("Dumps\\SingleShaders", NULL);
					CreateDirectory("Dumps\\SingleShaders\\VertexShader", NULL);

					auto _crc = VS_hash;
					char buffer[80];
					sprintf_s(buffer, 80, "Dumps\\SingleShaders\\VertexShader\\%08X.txt", _crc);
					fopen_s(&f, buffer, "wb");

					vector<byte> * v = origShaderData[_crc];
					fwrite(v->data(), 1, v->size(), f);
					fclose(f);
				}
			}
		}
		if (status == buttonPress::Down && !strcmp(Command.c_str(), "toggle_hunting")) {
			VS_hash = 0;
			PS_hash = 0;
			gl_hunt = !gl_hunt;
			HuntBeep();
			LogInfo("toggle_hunting\n");
		}
	}
	string Command;
	button* Button;
};
vector<HuntButtonHandler*> hBHs;

void frameFunction() {
	for (size_t i = 0; i < hBHs.size(); i++) {
		hBHs[i]->Handle();
	}
}

void hook(IDirect3DDevice9** ppDevice) {
	LogInfo("hook device: %p\n", *ppDevice);
	if (*ppDevice != NULL && !gl_hooked2) {
		DWORD*** vTable = (DWORD***)*ppDevice;

		gl_origPresent = (D3D9_P)(*vTable)[17];

		D3D9_DP gl_origDP = (D3D9_DP)(*vTable)[81];
		D3D9_DIP gl_origDIP = (D3D9_DIP)(*vTable)[82];
		D3D9_DPUP gl_origDPUP = (D3D9_DPUP)(*vTable)[83];
		D3D9_DIPUP gl_origDIPUP = (D3D9_DIPUP)(*vTable)[84];

		gl_origVS = (D3D9_VS)(*vTable)[91];
		gl_origVSSS = (D3D9_VSSS)(*vTable)[92];
		gl_origPS = (D3D9_PS)(*vTable)[106];
		gl_origPSSS = (D3D9_PSSS)(*vTable)[107];

		cHookMgr.Hook(&(sDrawPrimitive_Hook.nHookId), (LPVOID*)&(sDrawPrimitive_Hook.fnDrawPrimitive), gl_origDP, D3D9_DrawPrimitive);
		cHookMgr.Hook(&(sDrawIndexedPrimitive_Hook.nHookId), (LPVOID*)&(sDrawIndexedPrimitive_Hook.fnDrawIndexedPrimitive), gl_origDIP, D3D9_DrawIndexedPrimitive);
		cHookMgr.Hook(&(sDrawPrimitiveUP_Hook.nHookId), (LPVOID*)&(sDrawPrimitiveUP_Hook.fnDrawPrimitiveUP), gl_origDPUP, D3D9_DrawPrimitiveUP);
		//cHookMgr.Hook(&(sDrawIndexedPrimitiveUP_Hook.nHookId), (LPVOID*)&(sDrawIndexedPrimitiveUP_Hook.fnDrawIndexedPrimitiveUP), gl_origDIPUP, D3D9_DrawIndexedPrimitiveUP);

		cHookMgr.Hook(&(sCreateVS_Hook.nHookId), (LPVOID*)&(sCreateVS_Hook.fnCreateVS), gl_origVS, D3D9_CreateVS);
		cHookMgr.Hook(&(sCreatePS_Hook.nHookId), (LPVOID*)&(sCreatePS_Hook.fnCreatePS), gl_origPS, D3D9_CreatePS);
		cHookMgr.Hook(&(sVSSS_Hook.nHookId), (LPVOID*)&(sVSSS_Hook.fnVSSS), gl_origVSSS, D3D9_VSSetShader);
		cHookMgr.Hook(&(sPSSS_Hook.nHookId), (LPVOID*)&(sPSSS_Hook.fnPSSS), gl_origPSSS, D3D9_PSSetShader);

		cHookMgr.Hook(&(sPresent_Hook.nHookId), (LPVOID*)&(sPresent_Hook.fnPresent), gl_origPresent, D3D9_Present);

		gl_hooked2 = true;
	}
	gInitGfx = true;
	gStereoTexMgr->Init(*ppDevice);
}

HRESULT STDMETHODCALLTYPE D3D9_CreateDevice(
IDirect3D9* This, 
UINT Adapter, 
D3DDEVTYPE DeviceType, 
HWND hFocusWindow, 
DWORD BehaviorFlags, 
D3DPRESENT_PARAMETERS* pPresentationParameters, 
IDirect3DDevice9** ppReturnedDeviceInterface) {
	HRESULT res = sCreate_Hook.fnCreate(This, Adapter, DeviceType, hFocusWindow, BehaviorFlags, pPresentationParameters, ppReturnedDeviceInterface);
	hook(ppReturnedDeviceInterface);
	return res;
}

void hook(IDirect3D9* direct9) {
	LogInfo("Hook direct9\n");
	if (direct9 != NULL && !gl_hooked) {
		DWORD*** vTable = (DWORD***)direct9;
		gl_origCreate = (D3D9_Create)(*vTable)[16];
		cHookMgr.Hook(&(sCreate_Hook.nHookId), (LPVOID*)&(sCreate_Hook.fnCreate), gl_origCreate, D3D9_CreateDevice);
		gl_hooked = true;
	}
}

void ShowStartupScreen()
{
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
}

// Exported function (faking d3d9.dll's export)
IDirect3D9* WINAPI Direct3DCreate9(UINT SDKVersion) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"

	// Hooking IDirect3D Object from Original Library
	typedef IDirect3D9* (WINAPI* D3D9_Type)(UINT SDKVersion);
	D3D9_Type Direct3DCreate9_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "Direct3DCreate9");

	IDirect3D9* direct9 = Direct3DCreate9_fn(SDKVersion);
	hook(direct9);
	return direct9;
}

int WINAPI D3DPERF_BeginEvent(D3DCOLOR col, LPCWSTR wszName) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll	
		// Hooking IDirect3D Object from Original Library
	typedef int (WINAPI* D3D9_Type)(D3DCOLOR col, LPCWSTR wszName);
	D3D9_Type D3DPERF_BeginEvent_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_BeginEvent");
	return D3DPERF_BeginEvent_fn(col, wszName);
}

int WINAPI D3DPERF_EndEvent() {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"
		// Hooking IDirect3D Object from Original Library
	typedef int (WINAPI* D3D9_Type)();
	D3D9_Type D3DPERF_BeginEvent_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_EndEvent");
	return D3DPERF_BeginEvent_fn();
}

void WINAPI D3DPERF_SetMarker(D3DCOLOR col, LPCWSTR wszName) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"
		// Hooking IDirect3D Object from Original Library
	typedef void (WINAPI* D3D9_Type)(D3DCOLOR col, LPCWSTR wszName);
	D3D9_Type D3DPERF_SetMarker_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_SetMarker");
	D3DPERF_SetMarker_fn(col, wszName);
}

void WINAPI D3DPERF_SetRegion(D3DCOLOR col, LPCWSTR wszName) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"
		// Hooking IDirect3D Object from Original Library
	typedef void (WINAPI* D3D9_Type)(D3DCOLOR col, LPCWSTR wszName);
	D3D9_Type D3DPERF_SetRegion_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_SetRegion");
	D3DPERF_SetRegion_fn(col, wszName);
}

BOOL WINAPI D3DPERF_QueryRepeatFrame() {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"

	// Hooking IDirect3D Object from Original Library
	typedef BOOL (WINAPI* D3D9_Type)();
	D3D9_Type D3DPERF_QueryRepeatFrame_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_QueryRepeatFrame");

	return D3DPERF_QueryRepeatFrame_fn();
}

void WINAPI D3DPERF_SetOptions(DWORD dwOptions) {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"
		// Hooking IDirect3D Object from Original Library
	typedef void(WINAPI* D3D9_Type)(DWORD dwOptions);
	D3D9_Type D3DPERF_SetOptions_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_SetOptions");
	D3DPERF_SetOptions_fn(dwOptions);
}

DWORD WINAPI D3DPERF_GetStatus() {
	if (!gl_hOriginalDll) LoadOriginalDll(); // looking for the "right d3d9.dll"
		// Hooking IDirect3D Object from Original Library
	typedef DWORD(WINAPI* D3D9_Type)();
	D3D9_Type D3DPERF_GetStatus_fn = (D3D9_Type)GetProcAddress(gl_hOriginalDll, "D3DPERF_GetStatus");
	return D3DPERF_GetStatus_fn();
}

void InitInstance() 
{
	// Initialisation
	gl_hOriginalDll        = NULL;
	char setting[MAX_PATH];
	char INIfile[MAX_PATH];
	char LOGfile[MAX_PATH];

	_getcwd(cwd, MAX_PATH);
	_getcwd(INIfile, MAX_PATH);
	_getcwd(LOGfile, MAX_PATH);
	strcat_s(INIfile, MAX_PATH, "\\d3dx.ini");

	gl_log = GetPrivateProfileInt("Logging", "calls", gl_log, INIfile) > 0;
	gl_hunt = GetPrivateProfileInt("Hunting", "hunting", gl_hunt, INIfile) > 0;
	gl_dump = GetPrivateProfileInt("Rendering", "export_binary", gl_dump, INIfile) > 0;

	if (gl_dump) {
		CreateDirectory("Dumps", NULL);
		CreateDirectory("Dumps\\AllShaders", NULL);
		CreateDirectory("Dumps\\AllShaders\\PixelShaders", NULL);
		CreateDirectory("Dumps\\AllShaders\\VertexShaders", NULL);
	}
	
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
	
	if (gl_log) {
		if (LogFile == NULL) {
			strcat_s(LOGfile, MAX_PATH, "\\d3d9_log.txt");
			LogFile = _fsopen(LOGfile, "w", _SH_DENYNO);
			setvbuf(LogFile, NULL, _IONBF, 0);
		}
	}

	gStereoTexMgr = new nv::stereo::ParamTextureManagerD3D9;
}

void LoadOriginalDll(void)
{
    char buffer[MAX_PATH];
    
    // Getting path to system dir and to d3d8.dll
	::GetSystemDirectory(buffer,MAX_PATH);

	// Append dll name
	strcat_s(buffer, 80, "\\d3d9.dll");
	
	// try to load the system's d3d10.dll, if pointer empty
	if (!gl_hOriginalDll) gl_hOriginalDll = ::LoadLibrary(buffer);
}

void ExitInstance() 
{    
	// Release the system's d3d10.dll
	if (gl_hOriginalDll)
	{
		::FreeLibrary(gl_hOriginalDll);
	    gl_hOriginalDll = NULL;  
	}
}