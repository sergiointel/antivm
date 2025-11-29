#include <windows.h>
#include <iostream>
#include <vector>
#include <intrin.h>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
using u64 = unsigned long long;
using u32 = unsigned int;
using u8 = unsigned char;
#define FLG_BIOS 0x1
#define FLG_CPU  0x2
#define FLG_WMI  0x4
#define FLG_TIME 0x8

int wmi_cnt(IWbemServices* svc, const wchar_t* q) {
    IEnumWbemClassObject* e = 0;
    if(FAILED(svc->ExecQuery(SysAllocString(L"WQL"), SysAllocString(q), 32, 0, &e))) return 0;
    
    IWbemClassObject* o = 0;
    ULONG r = 0;
    int c = 0;
    while(e) {
        e->Next(-1, 1, &o, &r);
        if(!r) break;
        c++; o->Release();
    }
    e->Release();
    return c;
}

int main() {
    u32 res = 0;

    // qemu/vmware dont emu mobo sensors - they would have to emulate with custom drivers.
    HRESULT hr = CoInitializeEx(0, 0);
    if(SUCCEEDED(hr)) {
        hr = CoInitializeSecurity(0, -1, 0, 0, 0, 3, 0, 0, 0);
        IWbemLocator* loc = 0; IWbemServices* svc = 0;
        
        if(SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, 0, 1, IID_IWbemLocator, (void**)&loc))) {
            if(SUCCEEDED(loc->ConnectServer(SysAllocString(L"ROOT\\CIMV2"), 0, 0, 0, 0, 0, 0, &svc))) {
                CoSetProxyBlanket(svc, 10, 0, 0, 3, 3, 0, 0);
                
                // check for fans, cache, voltage. of what i could find nobody has been able to properly emulate this yet, so probably the most reliable.
                if(!wmi_cnt(svc, L"SELECT * FROM Win32_Fan")) res |= FLG_WMI;
                if(!wmi_cnt(svc, L"SELECT * FROM Win32_CacheMemory")) res |= FLG_WMI;
                if(!wmi_cnt(svc, L"SELECT * FROM Win32_VoltageProbe")) res |= FLG_WMI;
                
                svc->Release();
            }
            loc->Release();
        }
        CoUninitialize();
    }

    // 0x52534D42 is 'RSMB'
    DWORD sz = GetSystemFirmwareTable(0x52534D42, 0, 0, 0);
    if(sz) {
        std::vector<u8> buf(sz);
        GetSystemFirmwareTable(0x52534D42, 0, buf.data(), sz);
        u8* p = buf.data() + 8;
        u8* end = buf.data() + sz;

        while(p < end) {
            if(*p == 127) break;
            if(*p == 0 && *(p+1) > 0x12) {
                u64 chars = *(u64*)(p + 8);
                if((chars >> 3) & 1) res |= FLG_BIOS;
                
                // count set bits - real bios usually have more then 10
                int n = 0;
                for(int i=0; i<64; ++i) n += ((chars >> i) & 1);
                if(n < 10) res |= FLG_BIOS;
                break;
            }
            p += *(p+1);
            while(p < end-1 && (*p || *(p+1))) p++;
            p += 2;
        }
    }

    // timing n cpuid
    int cpu[4];
    
    // rdtscp check
    __cpuid(cpu, 0x80000001);
    if(!((cpu[3] >> 27) & 1)) res |= FLG_CPU;

    u64 t1 = __rdtsc();
    __cpuid(cpu, 0);
    u64 t2 = __rdtsc();
    // increased threshold slightly for more stability
    if((t2 - t1) > 1200) res |= FLG_TIME;

    if(res) {
        printf("vm detected. mask: %x\n", res);
        return 1;
    }
    printf("clean.\n");
    return 0;
}
