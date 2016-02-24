// proxydll.h
#pragma once
#include "stdafx.h"

// Exported function
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
	);

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
	);
// regular functions
typedef HRESULT(STDMETHODCALLTYPE* D3D11_VS)(
	ID3D11Device * This,
	_In_ const void *pShaderBytecode,
	_In_ SIZE_T BytecodeLength,
	_In_opt_ ID3D11ClassLinkage *pClassLinkage,
	_Out_opt_ ID3D11VertexShader **ppVertexShader);
static struct {
	SIZE_T nHookId;
	D3D11_VS fnCreateVertexShader;
} sCreateVertexShader_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D11_PS)(
	ID3D11Device * This,
	_In_ const void *pShaderBytecode,
	_In_ SIZE_T BytecodeLength,
	_In_opt_ ID3D11ClassLinkage *pClassLinkage,
	_Out_opt_ ID3D11PixelShader **ppPixelShader);
static struct {
	SIZE_T nHookId;
	D3D11_PS fnCreatePixelShader;
} sCreatePixelShader_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D11_GS)(
	ID3D11Device * This,
	_In_ const void *pShaderBytecode,
	_In_ SIZE_T BytecodeLength,
	_In_opt_ ID3D11ClassLinkage *pClassLinkage,
	_Out_opt_ ID3D11GeometryShader **ppGeometryShader);
static struct {
	SIZE_T nHookId;
	D3D11_GS fnCreateGeometryShader;
} sCreateGeometryShader_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D11_HS)(
	ID3D11Device * This,
	_In_ const void *pShaderBytecode,
	_In_ SIZE_T BytecodeLength,
	_In_opt_ ID3D11ClassLinkage *pClassLinkage,
	_Out_opt_ ID3D11HullShader **ppHullShader);
static struct {
	SIZE_T nHookId;
	D3D11_HS fnCreateHullShader;
} sCreateHullShader_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D11_DS)(
	ID3D11Device * This,
	_In_ const void *pShaderBytecode,
	_In_ SIZE_T BytecodeLength,
	_In_opt_ ID3D11ClassLinkage *pClassLinkage,
	_Out_opt_ ID3D11DomainShader **ppDomainShader);
static struct {
	SIZE_T nHookId;
	D3D11_DS fnCreateDomainShader;
} sCreateDomainShader_Hook = { 0, NULL };

typedef HRESULT(STDMETHODCALLTYPE* D3D11_CS)(
	ID3D11Device * This,
	_In_ const void *pShaderBytecode,
	_In_ SIZE_T BytecodeLength,
	_In_opt_ ID3D11ClassLinkage *pClassLinkage,
	_Out_opt_ ID3D11ComputeShader **ppComputeShader);
static struct {
	SIZE_T nHookId;
	D3D11_CS fnCreateComputeShader;
} sCreateComputeShader_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* D3D11_2D)(
	ID3D11Device * This,
	_In_ const D3D11_TEXTURE2D_DESC *pDesc,
	_In_opt_ const D3D11_SUBRESOURCE_DATA *pInitialData,
	_Out_opt_ ID3D11Texture2D **ppTexture2D);
static struct {
	SIZE_T nHookId;
	D3D11_2D fnCreateTexture2D;
} sCreateTexture2D_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* D3D11_3D)(
	ID3D11Device * This,
	_In_ const D3D11_TEXTURE3D_DESC *pDesc,
	_In_opt_ const D3D11_SUBRESOURCE_DATA *pInitialData,
	_Out_opt_ ID3D11Texture3D **ppTexture2D);
static struct {
	SIZE_T nHookId;
	D3D11_3D fnCreateTexture3D;
} sCreateTexture3D_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_Draw)(ID3D11DeviceContext * This, UINT VertexCount, UINT StartVertexLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_Draw fnDraw;
} sDraw_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawAuto)(ID3D11DeviceContext * This);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawAuto fnDrawAuto;
} sDrawAuto_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawIndexed)(ID3D11DeviceContext * This, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawIndexed fnDrawIndexed;
} sDrawIndexed_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawInstanced)(ID3D11DeviceContext * This, UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawInstanced fnDrawInstanced;
} sDrawInstanced_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DrawIndexedInstanced)(ID3D11DeviceContext * This, UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation);
static struct {
	SIZE_T nHookId;
	D3D11C_DrawIndexedInstanced fnDrawIndexedInstanced;
} sDrawIndexedInstanced_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_PSSS)(ID3D11DeviceContext * This, ID3D11PixelShader *pPixelShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_PSSS fnPSSetShader;
} sPSSetShader_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_VSSS)(ID3D11DeviceContext * This, ID3D11VertexShader *pVertexShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_VSSS fnVSSetShader;
} sVSSetShader_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_CSSS)(ID3D11DeviceContext * This, ID3D11ComputeShader *pComputeShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_CSSS fnCSSetShader;
} sCSSetShader_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_GSSS)(ID3D11DeviceContext * This, ID3D11GeometryShader *pComputeShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_GSSS fnGSSetShader;
} sGSSetShader_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_HSSS)(ID3D11DeviceContext * This, ID3D11HullShader *pHullShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_HSSS fnHSSetShader;
} sHSSetShader_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_DSSS)(ID3D11DeviceContext * This, ID3D11DomainShader *pDomainShader, ID3D11ClassInstance *const *ppClassInstances, UINT NumClassInstances);
static struct {
	SIZE_T nHookId;
	D3D11C_DSSS fnDSSetShader;
} sDSSetShader_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* DXGI_Present)(IDXGISwapChain* This, UINT SyncInterval, UINT Flags);
static struct {
	SIZE_T nHookId;
	DXGI_Present fnDXGI_Present;
} sDXGI_Present_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* DXGI_ResizeBuffers)(IDXGISwapChain* This, UINT BufferCount, UINT Width, UINT Height, DXGI_FORMAT NewFormat, UINT SwapChainFlags);
static struct {
	SIZE_T nHookId;
	DXGI_ResizeBuffers fnDXGI_ResizeBuffers;
} sDXGI_ResizeBuffers_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* DXGI_CSC1)(IDXGIFactory1 * This, IUnknown * pDevice, DXGI_SWAP_CHAIN_DESC * pDesc, IDXGISwapChain ** ppSwapChain);
static struct {
	SIZE_T nHookId;
	DXGI_CSC1 fnCreateSwapChain1;
} sCreateSwapChain_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_CSR)(ID3D11DeviceContext * This, ID3D11Resource *pDstResource, UINT DstSubresource, UINT DstX, UINT DstY, UINT DstZ, ID3D11Resource *pSrcResource, UINT SrcSubresource, const D3D11_BOX *pSrcBox);
static struct {
	SIZE_T nHookId;
	D3D11C_CSR fnCopySubresourceRegion;
} sCopySubresourceRegion_Hook = { 0, NULL };
typedef void(STDMETHODCALLTYPE* D3D11C_UNMAP)(ID3D11DeviceContext * This, ID3D11Resource *pResource, UINT Subresource);
static struct {
	SIZE_T nHookId;
	D3D11C_UNMAP fnUnmap;
} sUnmap_Hook = { 0, NULL };
typedef HRESULT(STDMETHODCALLTYPE* D3D11C_MAP)(ID3D11DeviceContext * This, ID3D11Resource *pResource, UINT Subresource, D3D11_MAP MapType, UINT MapFlags, D3D11_MAPPED_SUBRESOURCE *pMappedResource);
static struct {
	SIZE_T nHookId;
	D3D11C_MAP fnMap;
} sMap_Hook = { 0, NULL };

void InitInstance();
void ExitInstance();
void LoadOriginalDll();
void ShowStartupScreen();
void NvAPIOverride();
UINT64 GetTexture2DHash(ID3D11Texture2D *texture, bool log_new, struct ResourceInfo *resource_info);
bool ExpandRegionCopy(ID3D11Resource *pDstResource, UINT DstX, UINT DstY, ID3D11Resource *pSrcResource, const D3D11_BOX *pSrcBox, UINT *replaceDstX, D3D11_BOX *replaceBox);

const int INI_PARAMS_SIZE = 8;

enum class GetResolutionFrom {
	INVALID = -1,
	SWAP_CHAIN,
	DEPTH_STENCIL,
};

struct ResolutionInfo
{
	int width, height;
	GetResolutionFrom from;

	ResolutionInfo() :
		from(GetResolutionFrom::INVALID),
		width(-1),
		height(-1)
	{}
};

struct ResourceInfo
{
	D3D11_RESOURCE_DIMENSION type;
	union {
		D3D11_TEXTURE2D_DESC tex2d_desc;
		D3D11_TEXTURE3D_DESC tex3d_desc;
	};

	ResourceInfo() :
		type(D3D11_RESOURCE_DIMENSION_UNKNOWN)
	{}

	struct ResourceInfo & operator= (D3D11_TEXTURE2D_DESC desc)
	{
		type = D3D11_RESOURCE_DIMENSION_TEXTURE2D;
		tex2d_desc = desc;
		return *this;
	}

	struct ResourceInfo & operator= (D3D11_TEXTURE3D_DESC desc)
	{
		type = D3D11_RESOURCE_DIMENSION_TEXTURE3D;
		tex3d_desc = desc;
		return *this;
	}
};

// Used to avoid querying the render target dimensions twice in the common case
// we are going to store both width & height in separate ini params:
struct ParamOverrideCache {
	float rt_width, rt_height;

	ParamOverrideCache() :
		rt_width(-1),
		rt_height(-1)
	{}
};
struct DrawContext
{
	bool skip;
	bool override;
	float oldSeparation;
	float oldConvergence;
	ID3D11PixelShader *oldPixelShader;
	ID3D11VertexShader *oldVertexShader;

	DrawContext() :
		skip(false),
		override(false),
		oldSeparation(FLT_MAX),
		oldConvergence(FLT_MAX),
		oldVertexShader(NULL),
		oldPixelShader(NULL)
	{}
};

enum class ParamOverrideType {
	INVALID,
	VALUE,
	RT_WIDTH,
	RT_HEIGHT,
	RES_WIDTH,
	RES_HEIGHT,
	TEXTURE,	// Needs shader type and slot number specified in
				// [ShaderOverride]. [TextureOverride] sections can
				// specify filter_index=N to define the value passed in
				// here. Special values for no [TextureOverride]
				// section = 0.0, or [TextureOverride] with no
				// filter_index = 1.0
				// TODO:
				// DEPTH_ACTIVE
				// VERTEX_SHADER    (how best to pass these in?
				// HULL_SHADER       Maybe the low/hi 32bits of hash? Or all 64bits split in two?
				// DOMAIN_SHADER     Maybe an index or some other mapping? Perhaps something like Helix mod's texture CRCs?
				// GEOMETRY_SHADER   Or... maybe don't bother! We can already achieve this by setting the value in
				// PIXEL_SHADER      the partner shaders instead! Limiting to a single draw call would be helpful)
				// etc.
};
struct ParamOverride {
	ParamOverrideType type;
	float val;

	// For texture filters:
	char shader_type;
	unsigned texture_slot;

	ParamOverride() :
		type(ParamOverrideType::INVALID),
		val(FLT_MAX),
		shader_type(NULL),
		texture_slot(INT_MAX)
	{}
};
enum class DepthBufferFilter {
	INVALID = -1,
	NONE,
	DEPTH_ACTIVE,
	DEPTH_INACTIVE,
};
struct ShaderOverride {
	float separation;
	float convergence;
	bool skip;
	std::vector<int> iterations; // Only for separation changes, not shaders.
	std::vector<UINT64> indexBufferFilter;
	DepthBufferFilter depth_filter;
	UINT64 partner_hash;
	bool fake_o0;

	int depth_input;
	ID3D11Texture2D *depth_resource = NULL;
	ID3D11ShaderResourceView *depth_view = NULL;
	UINT depth_width, depth_height;

	ParamOverride x[INI_PARAMS_SIZE], y[INI_PARAMS_SIZE], z[INI_PARAMS_SIZE], w[INI_PARAMS_SIZE];

	ShaderOverride() :
		separation(FLT_MAX),
		convergence(FLT_MAX),
		skip(false),
		depth_filter(DepthBufferFilter::NONE),
		partner_hash(0),
		fake_o0(false),
		depth_input(0),
		depth_resource(NULL),
		depth_view(NULL),
		depth_width(0),
		depth_height(0)
	{}

	~ShaderOverride()
	{
		if (depth_resource)
			depth_resource->Release();

		if (depth_view)
			depth_view->Release();
	}
};
typedef std::unordered_map<UINT64, struct ShaderOverride> ShaderOverrideMap;

struct TextureOverride {
	int stereoMode;
	int format;
	std::vector<int> iterations;
	bool expand_region_copy;
	bool deny_cpu_read;
	float filter_index;

	TextureOverride() :
		stereoMode(-1),
		format(-1),
		expand_region_copy(false),
		deny_cpu_read(false),
		filter_index(1.0)
	{}
};
typedef std::unordered_map<UINT64, struct TextureOverride> TextureOverrideMap;

static void BeepSuccess()
{
	// High beep for success
	Beep(1800, 400);
}

static void BeepShort()
{
	// Short High beep
	Beep(1800, 100);
}

static void BeepFailure()
{
	// Bonk sound for failure.
	Beep(200, 150);
}

static void BeepFailure2()
{
	// Brnk, dunk sound for failure.
	Beep(300, 200); Beep(200, 150);
}