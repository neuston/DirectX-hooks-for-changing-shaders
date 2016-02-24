// proxydll.h
#pragma once
#include "stdafx.h"

// Exported function
HRESULT WINAPI D3D10CreateDevice(
	_In_   IDXGIAdapter *pAdapter,
	_In_   D3D10_DRIVER_TYPE DriverType,
	_In_   HMODULE Software,
	_In_   UINT Flags,
	_In_   UINT SDKVersion,
	_Out_  ID3D10Device **ppDevice
	);
HRESULT WINAPI D3D10CreateDeviceAndSwapChain(
	_In_   IDXGIAdapter *pAdapter,
	_In_   D3D10_DRIVER_TYPE DriverType,
	_In_   HMODULE Software,
	_In_   UINT Flags,
	_In_   UINT SDKVersion,
	_In_   DXGI_SWAP_CHAIN_DESC *pSwapChainDesc,
	_Out_  IDXGISwapChain **ppSwapChain,
	_Out_  ID3D10Device **ppDevice
	);
// regular functions
typedef HRESULT(STDMETHODCALLTYPE* D3D10_VS)(
	ID3D10Device * This,
	__in  const void *pShaderBytecode,
	__in  SIZE_T BytecodeLength,
	__out_opt  ID3D10VertexShader **ppVertexShader);
static struct {
	SIZE_T nHookId;
	D3D10_VS fnCreateVertexshader;
} sCreateVertexShader_Hook = { 1, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D10_PS)(
	ID3D10Device * This,
	__in  const void *pShaderBytecode,
	__in  SIZE_T BytecodeLength,
	__out_opt  ID3D10PixelShader **ppPixelShader);
static struct {
	SIZE_T nHookId;
	D3D10_PS fnCreatePixelshader;
} sCreatePixelShader_Hook = { 2, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D10_GS)(
	ID3D10Device * This,
	__in  const void *pShaderBytecode,
	__in  SIZE_T BytecodeLength,
	__out_opt  ID3D10GeometryShader **ppGeometryShader);
static struct {
	SIZE_T nHookId;
	D3D10_GS fnCreateGeometryShader;
} sCreateGeometryShader_Hook = { 3, NULL };

void InitInstance();
void ExitInstance();
void LoadOriginalDll();
void ShowStartupScreen();

