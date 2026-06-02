# Brutal

Windows kernel driver that hides network ports from tools like `netstat`.

It hooks `\Device\Nsi` and filters out matching port entries before they reach user-mode callers. Supports UDPv4, UDPv6, TCPv4, and TCPv6 — any protocol that uses NSI for enumeration.

## Build

Open `brutal.sln` in Visual Studio with the WDK installed and build both projects (driver + control app).

Or from the command line:

```
msbuild brutal.sln /p:Configuration=Release /p:Platform=x64
```

## Usage

Load the driver (`sc create` or `devcon`), then use `ctl`:

```
ctl add 56278     hide port 56278
ctl add 443       hide port 443
ctl list          show all hidden ports
ctl del 443       unhide port 443
ctl clear         unhide everything
```

The driver starts with an empty list. Ports are hidden from all NSI queries — `netstat -an`, `GetExtendedUdpTable`, etc.

## Unload

```
sc stop hideport
```

If the service was created with `sc create`, use `sc delete hideport` to remove it.

## How it works

The driver opens `\Device\Nsi` and replaces its `IRP_MJ_DEVICE_CONTROL` dispatch. When `NsiGetAllParameter` completes, a completion routine scans the returned entries by reading the port at offset 2 of each entry (the standard location in NSI endpoint structures). Matching entries are removed from the result before it reaches the caller.
