#include "pch.h"
#include <windows.h>
#include <cstdlib> 

typedef BOOL(WINAPI* PFSETWINDOWTEXTW)(HWND, LPCWSTR);

PFSETWINDOWTEXTW g_pOrgFunc = NULL; 

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        g_pOrgFunc = (PFSETWINDOWTEXTW)GetProcAddress(GetModuleHandle(L"user32.dll"), "SetWindowTextW");
        hook_iat("user32.dll", (PROC)(FARPROC)g_pOrgFunc, (PROC)(FARPROC)ex_SetWindowTextW);
        break;

    case DLL_PROCESS_DETACH:
        hook_iat("user32.dll", (PROC)(FARPROC)ex_SetWindowTextW, (PROC)(FARPROC)g_pOrgFunc);
        break;
    }
    return TRUE;
}

BOOL WINAPI ex_SetWindowTextW(HWND hWnd, LPWSTR lpString)
{
    const wchar_t* pNum = L"영일이삼사오육칠팔구";
    wchar_t temp[2] = { 0, };
    int i = 0, nLen = 0, nIndex = 0;

    nLen = wcslen(lpString);
    for (i = 0; i < nLen; i++)
    {
        if (L'0' <= lpString[i] && lpString[i] <= L'9') 
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp); 
            lpString[i] = pNum[nIndex];
        }
    }
    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}

BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    PBYTE pAddr;

    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;

    pAddr += ((DWORD)&pAddr[0x3C]);

    dwRVA = *((DWORD*)&pAddr[0x80]);

    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

    for (; pImportDesc->Name; pImportDesc++) 
    {
        szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);

        if (!stricmp(szLibName, szDllName))
        {
            pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);

            for (; pThunk->u1.Function; pThunk++)
            {
                if (pThunk->u1.Function == (DWORD)pfnOrg) 
                {
                    VirtualProtect((LPVOID)&pThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pThunk->u1.Function = (DWORD)pfnNew;

                    VirtualProtect((LPVOID)&pThunk->u1.Function, 4, dwOldProtect, &dwOldProtect);

                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}
