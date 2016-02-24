// proxydll.h
#pragma once

// Exported function
IDirect3D9* WINAPI Direct3DCreate9(UINT SDKVersion);
int WINAPI D3DPERF_BeginEvent(D3DCOLOR col, LPCWSTR wszName);
int WINAPI D3DPERF_EndEvent();
void WINAPI D3DPERF_SetMarker(D3DCOLOR col, LPCWSTR wszName);
void WINAPI D3DPERF_SetRegion(D3DCOLOR col, LPCWSTR wszName);
BOOL WINAPI D3DPERF_QueryRepeatFrame();
void WINAPI D3DPERF_SetOptions(DWORD dwOptions);
DWORD WINAPI D3DPERF_GetStatus();
// regular functions
typedef HRESULT(STDMETHODCALLTYPE* D3D9_Create)(IDirect3D9* This, UINT Adapter, D3DDEVTYPE DeviceType, HWND hFocusWindow, DWORD BehaviorFlags, D3DPRESENT_PARAMETERS* pPresentationParameters, IDirect3DDevice9** ppReturnedDeviceInterface);
static struct {
	SIZE_T nHookId;
	D3D9_Create fnCreate;
} sCreate_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* D3D9_PS)(IDirect3DDevice9 * This, CONST DWORD* pFunction, IDirect3DPixelShader9** ppShader);
static struct {
	SIZE_T nHookId;
	D3D9_PS fnCreatePS;
} sCreatePS_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_VS)(IDirect3DDevice9 * This, CONST DWORD* pFunction, IDirect3DVertexShader9** ppShader);
static struct {
	SIZE_T nHookId;
	D3D9_VS fnCreateVS;
} sCreateVS_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_VSSS)(IDirect3DDevice9 * This, IDirect3DVertexShader9* pShader);
static struct {
	SIZE_T nHookId;
	D3D9_VSSS fnVSSS;
} sVSSS_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_PSSS)(IDirect3DDevice9 * This, IDirect3DPixelShader9* pShader);
static struct {
	SIZE_T nHookId;
	D3D9_PSSS fnPSSS;
} sPSSS_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_P)(IDirect3DDevice9 * This, CONST RECT* pSourceRect, CONST RECT* pDestRect, HWND hDestWindowOverride, CONST RGNDATA* pDirtyRegion);
static struct {
	SIZE_T nHookId;
	D3D9_P fnPresent;
} sPresent_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_DP)(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, UINT StartVertex, UINT PrimitiveCount); 
static struct {
	SIZE_T nHookId;
	D3D9_DP fnDrawPrimitive;
} sDrawPrimitive_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_DIP)(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, INT BaseVertexIndex, UINT MinVertexIndex, UINT NumVertices, UINT startIndex, UINT primCount);
static struct {
	SIZE_T nHookId;
	D3D9_DIP fnDrawIndexedPrimitive;
} sDrawIndexedPrimitive_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_DPUP)(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, UINT PrimitiveCount, CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride); 
static struct {
	SIZE_T nHookId;
	D3D9_DPUP fnDrawPrimitiveUP;
} sDrawPrimitiveUP_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D9_DIPUP)(IDirect3DDevice9 * This, D3DPRIMITIVETYPE PrimitiveType, UINT MinVertexIndex, UINT NumVertices, UINT PrimitiveCount, CONST void* pIndexData, D3DFORMAT IndexDataFormat, CONST void* pVertexStreamZeroData, UINT VertexStreamZeroStride);
static struct {
	SIZE_T nHookId;
	D3D9_DIPUP fnDrawIndexedPrimitiveUP;
} sDrawIndexedPrimitiveUP_Hook = { 0, NULL };

void InitInstance();
void ExitInstance();
void LoadOriginalDll();
void frameFunction();
void ShowStartupScreen();
uint32_t crc32_fast(const void* data, size_t length, uint32_t previousCrc32 = 0);


