#!/bin/bash
# Produces the generated test samples, inside the factory image (see `build.sh`).
#
# `tests/samples` is mounted at /samples. Each family writes its outputs into the samples
# tree and skips an output that already exists, so a committed sample is never replaced
# by accident; `--force` regenerates.
#
#   generate.sh [--force] <family>...
#
# families: confuserex bitmono obfuscar jiejie (the packer samples), variants (metadata
# layouts and stream-directory experiments), sections (section layout experiments), debug
# (debug-information forms), pdb (Portable PDB probes), winmd, and oracle.
#
# `oracle` runs every sample on the .NET Framework 4.8 (under Wine), CoreCLR and Mono, and
# writes `factory/oracle.tsv`: whether each runtime runs the sample, and whether its output
# matches its unprotected build's (for the stream and section experiments, the output itself).

set -euo pipefail

readonly SAMPLES=/samples
readonly FACTORY=$SAMPLES/factory
readonly CACHE=/cache
readonly CONFUSEREX=$SAMPLES/packers/confuserex/1.6.0
readonly ORIGINAL=$CONFUSEREX/original.exe

# The ConfuserEx release the 1.6.0 samples come from.
readonly CONFUSEREX_URL=https://github.com/mkaring/ConfuserEx/releases/download/v1.6.0/ConfuserEx-CLI.zip
readonly CONFUSEREX_SHA256=a00de7cddc740f7edb1baab4c6c9073553dcc88f7e873d15b7fd34ddd33753d7

# The protectors the packer samples come from, each run as its .NET Framework build under
# Wine: run on .NET (Core) they bind the code they inject to the runtime they run on
# (System.Private.CoreLib, System.Runtime), and the output does not load on the .NET
# Framework 4.8 the samples target.
#
# BitMono at two versions, each a directory of samples protected from the same TestApp
# with the same configs: 0.39.0, which the techniques were written against, and 0.45.0,
# the current release (its DotNetHook no longer emits the invalid static stubs 0.39.0 does,
# upstream commit 17b12e2c).
readonly BITMONO_VERSIONS="0.39.0 0.45.0"
readonly BITMONO_SHA256_0_39_0=5e535ca43e76176be7546f065e427ce47a9d33e3fcf32c3bda9eea1832fe662a
readonly BITMONO_SHA256_0_45_0=fc3079e39ce0bfbdaa2bf91f4cf33b6959b4061b7032beb9c8cc0ac1b14c9f72
readonly OBFUSCAR_URL=https://www.nuget.org/api/v2/package/Obfuscar/2.2.50
readonly OBFUSCAR_SHA256=8790e1e36d613613311ec512129a6701c63576428692f20a95988a351fdc3187
readonly JIEJIE_URL=https://github.com/dcsoft-yyf/JIEJIE.NET/archive/d28aa56f68665c461fa919e3a1c7cec1a19706ad.tar.gz
readonly JIEJIE_SHA256=01b84e2278d3c1e95d4e26088d39da2893652a0d1b564f53f7857bfd2a7ba9ea
# JIEJIE disassembles its input with ildasm.exe; this is Microsoft's standalone build of it.
readonly ILDASM_URL=https://www.nuget.org/api/v2/package/runtime.win-x64.Microsoft.NETCore.ILDAsm/9.0.20
readonly ILDASM_SHA256=df6f062ed2b299a8dae058957241ac4cc103e0fb1b3d1703d00c64f9323ece7f

# A metadata-only assembly (a .winmd): Windows.Wdk.winmd from the MIT-licensed
# win32metadata project, 1.2 MB against Windows.Win32.winmd's 24 MB.
readonly WDKMETADATA_URL=https://www.nuget.org/api/v2/package/Microsoft.Windows.WDK.Win32Metadata/0.13.25-experimental
readonly WDKMETADATA_SHA256=79079a449d8f621052bcaf13039e411d1c1b77aec4a89cf04d96518d0a619617

FORCE=0

# Samples that crash must leave nothing in the samples tree: no core dumps, no Mono crash
# reports (both are written to the working directory, which is the sample's own).
ulimit -c 0
export MONO_CRASH_NOFILE=1

log() { echo "[factory] $*" >&2; }

# True when $1 must be (re)generated.
wanted() { [ "$FORCE" = 1 ] || [ ! -e "$1" ]; }

# Downloads $1 to $2 once and checks it against the sha256 $3.
fetch() {
    local url=$1 out=$2 sha=$3
    if [ ! -f "$out" ]; then
        log "fetching $url"
        curl -sSfL -o "$out.part" "$url"
        mv "$out.part" "$out"
    fi
    if [ -z "$sha" ]; then
        log "no pinned sha256 for $out; it is $(sha256sum "$out" | cut -d' ' -f1)"
        exit 1
    fi
    echo "$sha  $out" | sha256sum -c --quiet -
}

# Runs a .NET Framework executable under Wine with a timeout, stdout to $2.
run_netfx() {
    local exe=$1 out=$2
    (cd "$(dirname "$exe")" && timeout 120 wine "$(basename "$exe")" >"$out" 2>/dev/null)
}

# Runs an executable on Mono with a timeout, stdout to $2.
run_mono() {
    local exe=$1 out=$2
    (cd "$(dirname "$exe")" && timeout 120 mono "$(basename "$exe")" >"$out" 2>/dev/null)
}

# Runs an executable's entry point on CoreCLR (the CoreClrHost generator, built into
# $CORECLR_HOST) with a timeout, stdout to $2.
run_coreclr() {
    local exe=$1 out=$2
    (cd "$(dirname "$exe")" && timeout 120 dotnet "$CORECLR_HOST/CoreClrHost.dll" "$exe" >"$out" 2>/dev/null)
}

family_confuserex() {
    fetch "$CONFUSEREX_URL" "$CACHE/ConfuserEx-CLI.zip" "$CONFUSEREX_SHA256"
    local cli=$CACHE/confuserex
    [ -f "$cli/Confuser.CLI.exe" ] || unzip -q -o "$CACHE/ConfuserEx-CLI.zip" -d "$cli"

    local crproj name work
    for crproj in "$CONFUSEREX"/*.crproj; do
        name=$(basename "$crproj" .crproj)
        wanted "$CONFUSEREX/$name.exe" || continue
        log "confuserex: $name"
        work=$(mktemp -d)
        cp "$ORIGINAL" "$work/TestApp.exe"
        cp "$crproj" "$work/config.crproj"
        wine_console "$work" "$work/log.txt" "$cli/Confuser.CLI.exe" -n config.crproj \
            || { cat "$work/log.txt" >&2; log "confuserex: $name failed"; exit 1; }
        cp "$work/protected/TestApp.exe" "$CONFUSEREX/$name.exe"
        rm -rf "$work"
    done
}

# A short hash of the files in directory $1, for keying a cached build on its sources.
source_hash() {
    (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-12)
}

# Builds the .NET project in directory $1 from a copy, so no bin/ or obj/ lands in the
# samples tree, and prints the copy's output directory.
build_copy() {
    local src
    src=$(mktemp -d)
    cp -r "$1/." "$src"
    dotnet build "$src" -c Release -o "$src/out" >&2
    echo "$src/out"
}

# Runs a Windows command line under Wine with a pseudo-terminal, in directory $1, its
# output to $2. Several protectors use the console API, which fails without a console.
wine_console() {
    local dir=$1 log=$2 command=wine argument
    shift 2
    # `script` hands the command to a shell: quote each argument so a Windows path's
    # backslashes reach Wine as they are.
    for argument in "$@"; do
        command+=" '${argument//\'/\'\\\'\'}'"
    done
    # No stdin for `script`, which would otherwise read the caller's (a loop's input).
    (cd "$dir" && script -qec "$command" /dev/null >"$log" 2>&1 </dev/null)
}

# The Windows path Wine maps a Linux path to.
winpath() { echo "Z:${1//\//\\}"; }

# Copies the protected file a run left in directory $1 (the only .exe there) to $2.
take_output() {
    local found
    found=$(find "$1" -name '*.exe' | head -1)
    [ -n "$found" ] || { log "no output in $1"; exit 1; }
    cp "$found" "$2"
}

family_bitmono() {
    local version dir tool sha config name work
    for version in $BITMONO_VERSIONS; do
        dir=$SAMPLES/packers/bitmono/$version
        tool=$CACHE/bitmono-$version
        sha=BITMONO_SHA256_${version//./_}
        if [ ! -f "$tool/BitMono.CLI.exe" ]; then
            fetch "https://github.com/sunnamed434/BitMono/archive/refs/tags/$version.tar.gz" \
                "$CACHE/bitmono-$version.tar.gz" "${!sha}"
            work=$(mktemp -d)
            tar xzf "$CACHE/bitmono-$version.tar.gz" -C "$work"
            dotnet build "$work"/BitMono-*/src/BitMono.CLI/BitMono.CLI.csproj -c Release -f net462 -o "$tool" >&2
            rm -rf "$work"
        fi
        for config in "$dir"/bitmono_*.json; do
            name=$(basename "$config" .json)
            wanted "$dir/$name.exe" || continue
            log "bitmono $version: $name"
            work=$(mktemp -d)
            cp "$dir/original.exe" "$work/TestApp.exe"
            cp "$config" "$work/protections.json"
            wine_console "$work" "$work/log.txt" "$tool/BitMono.CLI.exe" --file TestApp.exe \
                --protections-file protections.json -o out \
                || { cat "$work/log.txt" >&2; log "bitmono $version: $name failed"; exit 1; }
            take_output "$work/out" "$dir/$name.exe"
            rm -rf "$work"
        done
    done
}

family_obfuscar() {
    local dir=$SAMPLES/packers/obfuscar/2.2.50 tool=$CACHE/obfuscar config name work out
    if [ ! -f "$tool/tools/Obfuscar.Console.exe" ]; then
        fetch "$OBFUSCAR_URL" "$CACHE/obfuscar.nupkg" "$OBFUSCAR_SHA256"
        mkdir -p "$tool"
        unzip -q -o "$CACHE/obfuscar.nupkg" 'tools/*' -d "$tool"
    fi
    for config in "$dir"/obfuscar_*.xml; do
        name=$(basename "$config" .xml)
        wanted "$dir/$name.exe" || continue
        log "obfuscar: $name"
        work=$(mktemp -d)
        cp "$dir/original.exe" "$work/TestApp.exe"
        cp "$config" "$work/config.xml"
        out=$(sed -n 's/.*name="OutPath" value="\([^"]*\)".*/\1/p' "$config")
        wine_console "$work" "$work/log.txt" "$tool/tools/Obfuscar.Console.exe" config.xml \
            || { cat "$work/log.txt" >&2; log "obfuscar: $name failed"; exit 1; }
        cp "$work/${out:-output}/TestApp.exe" "$dir/$name.exe"
        rm -rf "$work"
    done
}

# Each JIEJIE sample and its switches (none: JIEJIE's defaults).
readonly JIEJIE_VARIANTS="
jiejie_default
jiejie_strings_only +strings,-controlflow,-rename,-resources,-memberorder,-removemember
jiejie_highstrings +strings,+hightstrings,-controlflow,-rename,-resources,-memberorder,-removemember
jiejie_controlflow_only +controlflow,-strings,-rename,-resources,-removemember,-memberorder
jiejie_controlflow_no_rename +controlflow,-strings,-rename,-resources,-removemember,-memberorder
jiejie_rename_only +rename,-controlflow,-strings,-resources,-memberorder,-removemember
jiejie_resources_only +resources,-controlflow,-strings,-rename,-memberorder,-removemember
jiejie_no_rename -rename
jiejie_maximum +hightstrings
"

family_jiejie() {
    # The builds are cached under the hash of the generators that shape them, so editing
    # IlRetarget or IldasmShim rebuilds rather than reusing a build made without the edit.
    local dir=$SAMPLES/packers/jiejie/source work name switches tool sdk
    tool=$CACHE/jiejie-$(source_hash "$FACTORY/generators/IlRetarget")
    sdk=$CACHE/jiejie-sdk-$(source_hash "$FACTORY/generators/IldasmShim")
    if [ ! -f "$tool/JIEJIE.NetFx.exe" ]; then
        fetch "$JIEJIE_URL" "$CACHE/jiejie.tar.gz" "$JIEJIE_SHA256"
        work=$(mktemp -d)
        tar xzf "$CACHE/jiejie.tar.gz" -C "$work"
        # The repository's .NET Framework project file is DRM-encrypted; its .NET Core one
        # lists the same sources, so it is built for net48 without the DOTNETCORE define.
        local src
        src=$(echo "$work"/JIEJIE.NET-*/source)
        sed -e 's|<TargetFramework>netcoreapp3.1</TargetFramework>|<TargetFramework>net48</TargetFramework>|' \
            -e 's|TRACE;DOTNETCORE|TRACE|g' \
            "$src/JIEJIENETForCore.Console.csproj" >"$src/JIEJIE.NetFx.csproj"
        # Upstream defect: the IL templates JIEJIE injects (CodeTemplate.cs) name .NET (Core)
        # reference assemblies - System.Runtime, System.Collections, System.Threading,
        # System.Threading.Thread - outside their `#if DOTNETCORE` forms, and the .NET
        # Framework build maps none of them, so its output does not load on the .NET
        # Framework. IlRetarget points each at the assembly that defines the type there.
        local retarget
        retarget=$(build_copy "$FACTORY/generators/IlRetarget")
        wine_console "$src" "$work/retarget.txt" "$retarget/IlRetarget.exe" \
            "$(winpath "$src/JIEJIEEngine/CodeTemplate.cs")" \
            || { cat "$work/retarget.txt" >&2; log "jiejie: retargeting the templates failed"; exit 1; }
        sed 's/\r$//' "$work/retarget.txt" >&2
        rm -rf "$(dirname "$retarget")"
        dotnet build "$src/JIEJIE.NetFx.csproj" -c Release -p:GenerateAssemblyInfo=false -o "$tool" >&2
        rm -rf "$work"
    fi
    if [ ! -f "$sdk/ildasm.real.exe" ]; then
        fetch "$ILDASM_URL" "$CACHE/ildasm.nupkg" "$ILDASM_SHA256"
        local shim
        shim=$(build_copy "$FACTORY/generators/IldasmShim")
        mkdir -p "$sdk"
        cp "$shim"/* "$sdk/"
        rm -rf "$(dirname "$shim")"
        unzip -p "$CACHE/ildasm.nupkg" runtimes/win-x64/native/ildasm.exe >"$sdk/ildasm.real.exe"
    fi
    while read -r name switches; do
        [ -n "$name" ] || continue
        wanted "$dir/$name.exe" || continue
        log "jiejie: $name"
        work=$(mktemp -d)
        cp "$dir/original.exe" "$work/TestApp.exe"
        wine_console "$work" "$work/log.txt" "$tool/JIEJIE.NetFx.exe" \
            "input=$(winpath "$work/TestApp.exe")" "output=$(winpath "$work/out.exe")" \
            "sdkpath=$(winpath "$sdk")" ${switches:+"switch=$switches"} \
            || { cat "$work/log.txt" >&2; log "jiejie: $name failed"; exit 1; }
        [ -f "$work/out.exe" ] || { cat "$work/log.txt" >&2; log "jiejie: $name wrote nothing"; exit 1; }
        cp "$work/out.exe" "$dir/$name.exe"
        rm -rf "$work"
    done <<<"$JIEJIE_VARIANTS"
}

family_variants() {
    local layouts=$SAMPLES/metadata/layouts streams=$SAMPLES/metadata/streams
    if [ "$FORCE" = 0 ] && [ -d "$layouts" ] && [ -d "$streams" ]; then
        return
    fi
    log "variants"
    local variants probe
    variants=$(build_copy "$FACTORY/generators/MetadataVariants")
    probe=$(build_copy "$FACTORY/generators/StreamProbe")
    rm -rf "$layouts" "$streams"
    dotnet "$variants/MetadataVariants.dll" layouts "$ORIGINAL" "$layouts" >&2
    dotnet "$variants/MetadataVariants.dll" streams "$probe/StreamProbe.exe" "$streams" >&2
}

family_sections() {
    local sections=$SAMPLES/metadata/sections
    if [ "$FORCE" = 0 ] && [ -d "$sections" ]; then
        return
    fi
    log "sections"
    local layouts probe
    layouts=$(build_copy "$FACTORY/generators/SectionLayouts")
    probe=$(mktemp -d)
    # mcs leaves room in the headers for the section each experiment adds
    mcs -out:"$probe/SectionProbe.exe" "$FACTORY/generators/SectionProbe/Program.cs" >&2
    rm -rf "$sections"
    dotnet "$layouts/SectionLayouts.dll" "$probe/SectionProbe.exe" "$sections" >&2
    rm -rf "$probe" "$(dirname "$layouts")"
}

family_debug() {
    # TestApp built once per debug-information form, each in a directory of its own so the
    # `.pdb` beside an image is the one built with it.
    local form src out
    for form in portable embedded deterministic none; do
        out=$SAMPLES/debug/$form
        wanted "$out/TestApp.exe" || continue
        log "debug: $form"
        src=$(mktemp -d)
        cp -r "$SAMPLES/packers/source/TestApp/." "$src"
        local props=(-p:DebugType=portable -p:Deterministic=false)
        case $form in
            embedded) props=(-p:DebugType=embedded -p:Deterministic=false) ;;
            deterministic) props=(-p:DebugType=portable -p:Deterministic=true -p:PathMap="$src=/_/") ;;
            none) props=(-p:DebugType=none -p:Deterministic=false) ;;
        esac
        dotnet build "$src/TestApp.csproj" -c Release "${props[@]}" -o "$src/out" >&2
        mkdir -p "$out"
        cp "$src/out/TestApp.exe" "$out/"
        [ ! -f "$src/out/TestApp.pdb" ] || cp "$src/out/TestApp.pdb" "$out/"
        rm -rf "$src"
    done
}

family_pdb() {
    # PdbProbe, whose Portable PDB holds a row of every PDB table and a record of every custom
    # debug information kind C# writes, built per variant into a directory of its own. Debug
    # builds add the Edit and Continue and hoisted-scope records; the path map gives documents
    # the `/_/` names its SourceLink map covers, and a deterministic build a stable PDB id.
    local variant src out
    for variant in portable embedded release unmapped; do
        out=$SAMPLES/pdb/$variant
        wanted "$out/PdbProbe.dll" || continue
        log "pdb: $variant"
        src=$(mktemp -d)
        cp -r "$FACTORY/generators/PdbProbe" "$FACTORY/generators/PdbProbeLib" "$src/"
        local props=(-c Debug -p:DebugType=portable -p:Deterministic=true -p:PathMap="$src=/_/")
        case $variant in
            embedded) props=(-c Debug -p:DebugType=embedded -p:Deterministic=true -p:PathMap="$src=/_/") ;;
            release) props=(-c Release -p:DebugType=portable -p:Deterministic=true -p:PathMap="$src=/_/") ;;
            # Absolute document paths, no path map, and a PDB id that is not content-derived
            unmapped) props=(-c Debug -p:DebugType=portable -p:Deterministic=false) ;;
        esac
        dotnet build "$src/PdbProbe/PdbProbe.csproj" "${props[@]}" -o "$src/out" >&2
        mkdir -p "$out"
        cp "$src/out/PdbProbe.dll" "$src/out/PdbProbeLib.dll" "$out/"
        [ ! -f "$src/out/PdbProbe.pdb" ] || cp "$src/out/PdbProbe.pdb" "$out/"
        rm -rf "$src"
    done
    # The Visual Basic probe, for the records only Visual Basic writes
    out=$SAMPLES/pdb/vb
    if wanted "$out/PdbProbeVb.dll"; then
        log "pdb: vb"
        src=$(mktemp -d)
        cp -r "$FACTORY/generators/PdbProbeVb" "$src/"
        dotnet build "$src/PdbProbeVb/PdbProbeVb.vbproj" -c Debug -p:DebugType=portable \
            -p:Deterministic=true -p:PathMap="$src=/_/" -o "$src/out" >&2
        mkdir -p "$out"
        cp "$src/out/PdbProbeVb.dll" "$src/out/PdbProbeVb.pdb" "$out/"
        rm -rf "$src"
    fi
}

family_winmd() {
    local out=$SAMPLES/winmd/Windows.Wdk.winmd
    wanted "$out" || return 0
    fetch "$WDKMETADATA_URL" "$CACHE/wdkmetadata.nupkg" "$WDKMETADATA_SHA256"
    mkdir -p "$(dirname "$out")"
    unzip -p "$CACHE/wdkmetadata.nupkg" Windows.Wdk.winmd >"$out"
}

# Every sample and the reference its output is compared with: a packer sample with the
# unprotected build in its own directory, a layout or debug-form variant with TestApp, and a
# stream or section experiment with nothing (its output is recorded instead).
oracle_samples() {
    local exe
    find "$SAMPLES/packers" -name '*.exe' | sort | while read -r exe; do
        [ "$(basename "$exe")" = original.exe ] || echo "$exe $(dirname "$exe")/original.exe"
    done
    find "$SAMPLES/metadata/layouts" "$SAMPLES/debug" -name '*.exe' | sort | while read -r exe; do
        echo "$exe $ORIGINAL"
    done
    find "$SAMPLES/metadata/streams" "$SAMPLES/metadata/sections" -name '*.exe' | sort | while read -r exe; do
        echo "$exe -"
    done
}

# One runtime's verdict on a sample as three tab-separated fields: whether it runs, whether
# its output matches its reference ($3, or - for none), and the output itself when there is
# no reference. $4 caches the references' outputs.
verdict() {
    local runtime=$1 exe=$2 reference=$3 cache=$4 out expected runs matches=- output=-
    out=$(mktemp)
    if "run_$runtime" "$exe" "$out"; then runs=yes; else runs=no; fi
    if [ "$reference" != - ]; then
        expected=$cache/$runtime-$(echo "$reference" | sha256sum | cut -d' ' -f1)
        [ -f "$expected" ] || "run_$runtime" "$reference" "$expected" || true
        if cmp -s "$out" "$expected"; then
            matches=yes
        elif cmp -s <(sort "$out") <(sort "$expected"); then
            matches=unordered
        else
            matches=no
        fi
    elif [ "$runs" = yes ]; then
        output=$(tr -d '\r' <"$out" | paste -sd'|')
    fi
    rm -f "$out"
    printf '%s\t%s\t%s' "$runs" "$matches" "${output:--}"
}

family_oracle() {
    local cache
    cache=$(mktemp -d)
    CORECLR_HOST=$(build_copy "$FACTORY/generators/CoreClrHost")
    {
        printf '# Generated by factory/generate.sh oracle: each sample run on the .NET Framework 4.8\n'
        printf '# (under Wine), on CoreCLR %s and on Mono %s.\n' "$(dotnet --version)" \
            "$(mono --version | sed -n '1s/.*version \([^ ]*\).*/\1/p')"
        printf '# runs: the process exited 0. matches: its stdout\n'
        printf '# equals its unprotected build'"'"'s on the same runtime; unordered: the same lines in\n'
        printf '# another order (JIEJIE reorders manifest resources); - for a stream or section experiment.\n'
        printf '# output: a stream or section experiment'"'"'s stdout, lines joined by |.\n'
        printf 'path\tsha256'
        printf '\t%s_runs\t%s_matches\t%s_output' netfx netfx netfx coreclr coreclr coreclr mono mono mono
        printf '\n'
        local exe reference rel netfx coreclr mono
        while read -r exe reference; do
            rel=${exe#"$SAMPLES/"}
            netfx=$(verdict netfx "$exe" "$reference" "$cache")
            coreclr=$(verdict coreclr "$exe" "$reference" "$cache")
            mono=$(verdict mono "$exe" "$reference" "$cache")
            printf '%s\t%s\t%s\t%s\t%s\n' "$rel" "$(sha256sum "$exe" | cut -d' ' -f1)" \
                "$netfx" "$coreclr" "$mono"
            log "oracle: $rel netfx=${netfx%%$'\t'*} coreclr=${coreclr%%$'\t'*} mono=${mono%%$'\t'*}"
        done < <(oracle_samples)
    } >"$FACTORY/oracle.tsv"
    rm -rf "$cache" "$(dirname "$CORECLR_HOST")"
}

# Files the run created belong to the user who started it (`build.sh` passes OWNER), not
# to the container's root, so they can be committed as they are.
hand_back() {
    [ -n "${OWNER:-}" ] || return 0
    find "$SAMPLES" -user 0 -exec chown "$OWNER" {} +
}
trap hand_back EXIT

# Fails the run if a family or a sample left a crash artifact in the samples tree.
check_clean() {
    local stray
    stray=$(find "$SAMPLES" \( -name 'core.[0-9]*' -o -name 'mono_crash.*' \) | sort)
    [ -z "$stray" ] || { log "stray files left in the samples tree:"; echo "$stray" >&2; exit 1; }
}

if [ "${1:-}" = "--force" ]; then FORCE=1; shift; fi
[ "$#" -gt 0 ] || { echo "usage: generate.sh [--force] <family>..." >&2; exit 2; }
mkdir -p "$CACHE"
for family in "$@"; do
    case $family in
        confuserex | bitmono | obfuscar | jiejie | variants | sections | debug | pdb | winmd | oracle) "family_$family" ;;
        *) echo "unknown family '$family'" >&2; exit 2 ;;
    esac
done
check_clean
