# syntax=docker/dockerfile:1
#
# The test-sample factory: the tools that produce dotscope's generated samples, and the
# runtimes that check each one runs.
#
# `build.sh` builds this image on first use (and whenever this file changes) and runs it
# with `tests/samples` bind-mounted, so editing a protection config or a generator needs no
# image rebuild.
#
# Three runtimes:
# - .NET Framework 4.8 under Wine runs the protectors (each as its .NET Framework build)
#   and is the oracle that a generated sample loads and runs on the CLR it targets.
# - The Linux .NET SDK builds the small generators (the dnlib writer, the debug-directory
#   variants), which need no Windows runtime, and is the oracle's CoreCLR.
# - Mono is the oracle's runtime for the protections built for Mono alone.
#
# Arch rather than Debian because its Wine is the "new WoW64" build: it runs a 32-bit PE
# with no 32-bit Linux userspace. The first layer is the inno and visualbasic fixture
# images' own, so the three share it.
FROM archlinux:base

# Xvfb because the .NET Framework installer creates windows even when quiet, and Wine has
# no display driver to create them on without one.
RUN pacman -Syu --noconfirm --needed wine curl xorg-server-xvfb \
    && pacman -Scc --noconfirm

RUN pacman -Syu --noconfirm --needed winetricks cabextract unzip dotnet-sdk \
    && pacman -Scc --noconfirm

# The prefix, provisioned once here rather than on every run. `dotnet48` installs the real
# .NET Framework rather than leaving wine-mono to stand in for it: the samples are checked
# against the CLR they target, and ConfuserEx runs on it.
ENV WINEPREFIX=/opt/wine
ENV WINEDEBUG=-all
RUN wineboot -u && wineserver -w \
    && xvfb-run -a winetricks -q dotnet48 \
    && wineserver -w \
    && rm -rf /root/.cache/winetricks

# Mono, the oracle's third runtime: some BitMono protections are built for it alone
# (`[RuntimeMonikerMono]`) and are refused by both CLRs by design. Installed from the
# package database the first layer synced, so the Wine layers above are not upgraded.
RUN pacman -S --noconfirm --needed mono && pacman -Scc --noconfirm

# A sample that crashes exits with its error instead of starting winedbg, which would wait
# on a debugger session nobody attaches to.
ENV WINEDLLOVERRIDES="winedbg.exe=d"

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1
ENV DOTNET_NOLOGO=1
