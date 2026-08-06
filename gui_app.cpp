#include "gui_app.h"
#include "logger.h"
#include "vgk_manager.h"
#include "pipe_server.h"
#include "console_ui.h"

#include "imgui.h"
#include "backends/imgui_impl_win32.h"
#include "backends/imgui_impl_dx11.h"

#include <d3d11.h>
#include <dxgi.h>
#include <tchar.h>
#include <vector>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

static bool CreateDeviceD3D(HWND hWnd);
static void CleanupDeviceD3D();
static void CreateRenderTarget();
static void CleanupRenderTarget();
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

int RunGuiApp(HINSTANCE hInstance, int nCmdShow)
{
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L,
                      hInstance, nullptr, nullptr, nullptr, nullptr,
                      _T("TechnoVerseClass"), nullptr };
    ::RegisterClassEx(&wc);

    HWND hwnd = ::CreateWindow(wc.lpszClassName, _T("Techno Verse"),
                               WS_OVERLAPPEDWINDOW, 100, 100, 960, 640,
                               nullptr, nullptr, wc.hInstance, nullptr);

    HICON hIcon = (HICON)LoadImageW(nullptr, L"logo.ico", IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
    if (hIcon) {
        SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Set dark theme style
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 6.0f;
    style.FrameRounding = 4.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;
    style.GrabRounding = 4.0f;

    // Custom color accents
    style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.12f, 0.18f, 1.0f);
    style.Colors[ImGuiCol_Header]        = ImVec4(0.20f, 0.25f, 0.35f, 1.0f);
    style.Colors[ImGuiCol_Button]        = ImVec4(0.18f, 0.35f, 0.55f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.25f, 0.45f, 0.70f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive]  = ImVec4(0.15f, 0.30f, 0.50f, 1.0f);

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    bool done = false;
    while (!done && !g_shutdown.load())
    {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // Render main dashboard window
        ImGui::SetNextWindowPos(ImVec2(0, 0), ImGuiCond_Always);
        ImGui::SetNextWindowSize(io.DisplaySize, ImGuiCond_Always);
        ImGui::Begin("Techno Verse Dashboard", nullptr, 
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse);

        // Header Separator
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // System status variables
        ActiveSessionInfo active_snapshot;
        {
            std::lock_guard<std::mutex> lk(g_display_mtx);
            active_snapshot = g_active_session;
        }

        const uint32_t valorant_pid = GetValorantPID();
        const bool valorant_running = valorant_pid != 0;
        const bool keepalive_running = g_keepalive_running.load();
        const int reauth_remaining = g_gateway_reauth_remaining_sec.load();

        std::string session_age = "--:--:--";
        if (active_snapshot.active) {
            auto now = std::chrono::steady_clock::now();
            int secs = (int)std::chrono::duration_cast<std::chrono::seconds>(
                now - active_snapshot.start_time).count();
            session_age = FormatClock(secs);
        }

        // Status Card Grid (Full Width)
        ImGui::BeginChild("StatusChild", ImVec2(0, 210), true);
        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.0f, 1.0f), "SYSTEM STATUS");
        ImGui::Separator();

        ImGui::Text("Runtime:"); ImGui::SameLine(180);
        if (valorant_running)
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "VALORANT DETECTED");
        else
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "WAITING FOR VALORANT");

        ImGui::Text("Gateway Session:"); ImGui::SameLine(180);
        if (keepalive_running)
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "ACTIVE - READY TO QUEUE");
        else
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "IDLE");

        ImGui::Text("Reauth Timer:"); ImGui::SameLine(180);
        ImGui::TextColored(ImVec4(0.0f, 0.85f, 1.0f, 1.0f), "%s", FormatClock(reauth_remaining).c_str());

        ImGui::Text("Valorant PID:"); ImGui::SameLine(180);
        if (valorant_running)
            ImGui::Text("%u", valorant_pid);
        else
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "--");

        ImGui::Text("Session State:"); ImGui::SameLine(180);
        if (active_snapshot.active)
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "ACTIVE");
        else
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.0f, 1.0f), "NOT RUNNING");

        ImGui::Text("Session Age:"); ImGui::SameLine(180);
        ImGui::Text("%s", session_age.c_str());

        ImGui::Spacing();
        ImGui::Separator();
        if (ImGui::Button(" [F2] Refresh Session ", ImVec2(200, 30))) {
            TriggerGatewayAutoRefreshAction();
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Live Log Box
        ImGui::TextColored(ImVec4(1.0f, 0.85f, 0.0f, 1.0f), "LIVE SYSTEM LOGS");
        ImGui::BeginChild("LogBox", ImVec2(0, ImGui::GetContentRegionAvail().y - 10), true, ImGuiWindowFlags_HorizontalScrollbar);
        
        std::vector<std::string> log_snapshot;
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            log_snapshot = g_log_lines;
        }

        if (log_snapshot.empty()) {
            ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Waiting for system logs...");
        } else {
            for (const auto& line : log_snapshot) {
                if (line.find("OK") != std::string::npos || line.find("CREATED") != std::string::npos) {
                    ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.5f, 1.0f), "%s", line.c_str());
                } else if (line.find("WARN") != std::string::npos || line.find("FAILED") != std::string::npos) {
                    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", line.c_str());
                } else {
                    ImGui::TextUnformatted(line.c_str());
                }
            }
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);

        ImGui::EndChild();

        ImGui::End();

        ImGui::Render();

        const float clear_color[4] = { 0.08f, 0.08f, 0.10f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}

static bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;
#ifdef _DEBUG
    createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = {
        D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0
    };

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags,
        featureLevelArray, 2, D3D11_SDK_VERSION,
        &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext
    );

    if (res != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer)
    {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

static void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;

    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}
