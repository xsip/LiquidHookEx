/**
 * create_shellcode_project.cpp
 *
 * Scaffolds an x86 Shellcode DLL Visual Studio project with all required
 * compiler/linker settings for use with ShellcodeDLL86 / LiquidHookEx.
 *
 * Build (MSVC):
 *   cl /std:c++17 /EHsc /O2 /Fe:create_shellcode_project.exe create_shellcode_project.cpp
 *
 * Build (GCC / Clang):
 *   g++ -std=c++17 -O2 -o create_shellcode_project create_shellcode_project.cpp
 *
 * Usage:
 *   create_shellcode_project <ProjectName> [OutputDir]
 *
 * Example:
 *   create_shellcode_project GetCoins ./Projects
 *
 * Output layout:
 *   <OutputDir>/<ProjectName>/
 *     <ProjectName>.vcxproj
 *     <ProjectName>.def
 *     Include/<ProjectName>/
 *       Include.h
 *       Macros.h
 *     Source/<ProjectName>/
 *       Source.cpp
 */

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

// ── GUID generation ───────────────────────────────────────────────────────────

static std::string make_guid()
{
    std::random_device                      rd;
    std::mt19937_64                         rng(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    std::array<uint32_t, 4> d = { dist(rng), dist(rng), dist(rng), dist(rng) };

    // RFC 4122 v4: set version and variant bits
    d[1] = (d[1] & 0xFFFF0FFF) | 0x00004000;
    d[2] = (d[2] & 0x3FFFFFFF) | 0x80000000;

    char buf[40];
    std::snprintf(buf, sizeof(buf),
        "{%08X-%04X-%04X-%04X-%04X%08X}",
        d[0],
        (d[1] >> 16) & 0xFFFF,
        (d[1]) & 0xFFFF,
        (d[2] >> 16) & 0xFFFF,
        (d[2]) & 0xFFFF,
        d[3]);
    return buf;
}

// ── String helpers ────────────────────────────────────────────────────────────

static std::string replace_all(std::string s,
    const std::string& from,
    const std::string& to)
{
    for (std::size_t pos = 0;
        (pos = s.find(from, pos)) != std::string::npos;
        pos += to.size())
        s.replace(pos, from.size(), to);
    return s;
}

// Substitute %%NAME%% and %%GUID%% placeholders.
static std::string fill(const std::string& tmpl,
    const std::string& name,
    const std::string& guid = "")
{
    std::string s = replace_all(tmpl, "%%NAME%%", name);
    if (!guid.empty())
        s = replace_all(s, "%%GUID%%", guid);
    return s;
}

// ── File writing ──────────────────────────────────────────────────────────────

static void write_file(const fs::path& path, const std::string& content)
{
    fs::create_directories(path.parent_path());

    std::ofstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open for writing: " + path.string());

    // CRLF line endings -- MSVC / Visual Studio convention
    for (char c : content) {
        if (c == '\n') f.put('\r');
        f.put(c);
    }

    std::printf("  created  %s\n", path.string().c_str());
}

// ── Embedded file templates ───────────────────────────────────────────────────
// Placeholders:  %%NAME%%  project name
//                %%GUID%%  project GUID  (vcxproj only)

static const char* VCXPROJ_TEMPLATE()
{
    static const char data[] =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
        "<Project DefaultTargets=\"Build\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">\n"
        "\n"
        "  <ItemGroup Label=\"ProjectConfigurations\">\n"
        "    <ProjectConfiguration Include=\"Debug|Win32\">\n"
        "      <Configuration>Debug</Configuration>\n"
        "      <Platform>Win32</Platform>\n"
        "    </ProjectConfiguration>\n"
        "    <ProjectConfiguration Include=\"Release|Win32\">\n"
        "      <Configuration>Release</Configuration>\n"
        "      <Platform>Win32</Platform>\n"
        "    </ProjectConfiguration>\n"
        "    <ProjectConfiguration Include=\"Debug|x64\">\n"
        "      <Configuration>Debug</Configuration>\n"
        "      <Platform>x64</Platform>\n"
        "    </ProjectConfiguration>\n"
        "    <ProjectConfiguration Include=\"Release|x64\">\n"
        "      <Configuration>Release</Configuration>\n"
        "      <Platform>x64</Platform>\n"
        "    </ProjectConfiguration>\n"
        "  </ItemGroup>\n"
        "\n"
        "  <PropertyGroup Label=\"Globals\">\n"
        "    <VCProjectVersion>18.0</VCProjectVersion>\n"
        "    <Keyword>Win32Proj</Keyword>\n"
        "    <ProjectGuid>%%GUID%%</ProjectGuid>\n"
        "    <RootNamespace>%%NAME%%</RootNamespace>\n"
        "    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>\n"
        "  </PropertyGroup>\n"
        "\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.Default.props\" />\n"
        "\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|Win32'\" Label=\"Configuration\">\n"
        "    <ConfigurationType>DynamicLibrary</ConfigurationType>\n"
        "    <UseDebugLibraries>true</UseDebugLibraries>\n"
        "    <PlatformToolset>v145</PlatformToolset>\n"
        "    <CharacterSet>MultiByte</CharacterSet>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|Win32'\" Label=\"Configuration\">\n"
        "    <ConfigurationType>DynamicLibrary</ConfigurationType>\n"
        "    <UseDebugLibraries>false</UseDebugLibraries>\n"
        "    <PlatformToolset>v145</PlatformToolset>\n"
        "    <WholeProgramOptimization>true</WholeProgramOptimization>\n"
        "    <CharacterSet>MultiByte</CharacterSet>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\" Label=\"Configuration\">\n"
        "    <ConfigurationType>StaticLibrary</ConfigurationType>\n"
        "    <UseDebugLibraries>true</UseDebugLibraries>\n"
        "    <PlatformToolset>v145</PlatformToolset>\n"
        "    <CharacterSet>MultiByte</CharacterSet>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\" Label=\"Configuration\">\n"
        "    <ConfigurationType>StaticLibrary</ConfigurationType>\n"
        "    <UseDebugLibraries>false</UseDebugLibraries>\n"
        "    <PlatformToolset>v145</PlatformToolset>\n"
        "    <WholeProgramOptimization>true</WholeProgramOptimization>\n"
        "    <CharacterSet>MultiByte</CharacterSet>\n"
        "  </PropertyGroup>\n"
        "\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.props\" />\n"
        "  <ImportGroup Label=\"ExtensionSettings\" />\n"
        "  <ImportGroup Label=\"Shared\" />\n"
        "\n"
        "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='Debug|Win32'\">\n"
        "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\"\n"
        "            Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\"\n"
        "            Label=\"LocalAppDataPlatform\" />\n"
        "  </ImportGroup>\n"
        "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='Release|Win32'\">\n"
        "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\"\n"
        "            Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\"\n"
        "            Label=\"LocalAppDataPlatform\" />\n"
        "  </ImportGroup>\n"
        "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\n"
        "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\"\n"
        "            Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\"\n"
        "            Label=\"LocalAppDataPlatform\" />\n"
        "  </ImportGroup>\n"
        "  <ImportGroup Label=\"PropertySheets\" Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\n"
        "    <Import Project=\"$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props\"\n"
        "            Condition=\"exists('$(UserRootDir)\\Microsoft.Cpp.$(Platform).user.props')\"\n"
        "            Label=\"LocalAppDataPlatform\" />\n"
        "  </ImportGroup>\n"
        "\n"
        "  <PropertyGroup Label=\"UserMacros\" />\n"
        "\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|Win32'\">\n"
        "    <OutDir>$(SolutionDir)Bin\\$(Platform)\\$(Configuration)\\</OutDir>\n"
        "    <IntDir>$(SolutionDir)Intermediate\\$(Platform)\\$(Configuration)\\$(ProjectName)\\</IntDir>\n"
        "    <IncludePath>$(ProjectDir)Include;$(IncludePath)</IncludePath>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|Win32'\">\n"
        "    <OutDir>$(SolutionDir)Bin\\$(Platform)\\$(Configuration)\\</OutDir>\n"
        "    <IntDir>$(SolutionDir)Intermediate\\$(Platform)\\$(Configuration)\\$(ProjectName)\\</IntDir>\n"
        "    <IncludePath>$(ProjectDir)Include;$(IncludePath)</IncludePath>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\n"
        "    <OutDir>$(SolutionDir)Bin\\$(Platform)\\$(Configuration)\\</OutDir>\n"
        "    <IntDir>$(SolutionDir)Intermediate\\$(Platform)\\$(Configuration)\\$(ProjectName)\\</IntDir>\n"
        "    <IncludePath>$(ProjectDir)Include;$(IncludePath)</IncludePath>\n"
        "  </PropertyGroup>\n"
        "  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\n"
        "    <OutDir>$(SolutionDir)Bin\\$(Platform)\\$(Configuration)\\</OutDir>\n"
        "    <IntDir>$(SolutionDir)Intermediate\\$(Platform)\\$(Configuration)\\$(ProjectName)\\</IntDir>\n"
        "    <IncludePath>$(ProjectDir)Include;$(IncludePath)</IncludePath>\n"
        "  </PropertyGroup>\n"
        "\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|Win32'\">\n"
        "    <ClCompile>\n"
        "      <WarningLevel>Level3</WarningLevel>\n"
        "      <SDLCheck>true</SDLCheck>\n"
        "      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\n"
        "      <ConformanceMode>true</ConformanceMode>\n"
        "      <LanguageStandard>stdcpp23</LanguageStandard>\n"
        "      <LanguageStandard_C>stdclatest</LanguageStandard_C>\n"
        "      <BufferSecurityCheck>false</BufferSecurityCheck>\n"
        "      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>\n"
        "      <BasicRuntimeChecks>Default</BasicRuntimeChecks>\n"
        "    </ClCompile>\n"
        "    <Link>\n"
        "      <SubSystem>Console</SubSystem>\n"
        "      <GenerateDebugInformation>true</GenerateDebugInformation>\n"
        "      <AdditionalOptions>/MERGE:.hookd=.hook /MERGE:.hookb=.hook /OPT:NOICF %(AdditionalOptions)</AdditionalOptions>\n"
        "      <ModuleDefinitionFile>%%NAME%%.def</ModuleDefinitionFile>\n"
        "      <EnableCOMDATFolding>false</EnableCOMDATFolding>\n"
        "    </Link>\n"
        "  </ItemDefinitionGroup>\n"
        "\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|Win32'\">\n"
        "    <ClCompile>\n"
        "      <WarningLevel>Level3</WarningLevel>\n"
        "      <FunctionLevelLinking>true</FunctionLevelLinking>\n"
        "      <IntrinsicFunctions>true</IntrinsicFunctions>\n"
        "      <SDLCheck>true</SDLCheck>\n"
        "      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\n"
        "      <ConformanceMode>true</ConformanceMode>\n"
        "      <LanguageStandard>stdcpp23</LanguageStandard>\n"
        "      <LanguageStandard_C>stdclatest</LanguageStandard_C>\n"
        "      <BufferSecurityCheck>false</BufferSecurityCheck>\n"
        "      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>\n"
        "    </ClCompile>\n"
        "    <Link>\n"
        "      <SubSystem>Console</SubSystem>\n"
        "      <GenerateDebugInformation>true</GenerateDebugInformation>\n"
        "      <AdditionalOptions>/MERGE:.hookd=.hook /MERGE:.hookb=.hook /OPT:NOICF %(AdditionalOptions)</AdditionalOptions>\n"
        "      <ModuleDefinitionFile>%%NAME%%.def</ModuleDefinitionFile>\n"
        "      <EnableCOMDATFolding>false</EnableCOMDATFolding>\n"
        "    </Link>\n"
        "  </ItemDefinitionGroup>\n"
        "\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\">\n"
        "    <ClCompile>\n"
        "      <WarningLevel>Level3</WarningLevel>\n"
        "      <SDLCheck>true</SDLCheck>\n"
        "      <PreprocessorDefinitions>_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\n"
        "      <ConformanceMode>true</ConformanceMode>\n"
        "      <LanguageStandard>stdcpp23</LanguageStandard>\n"
        "      <LanguageStandard_C>stdclatest</LanguageStandard_C>\n"
        "    </ClCompile>\n"
        "    <Link>\n"
        "      <SubSystem>Console</SubSystem>\n"
        "      <GenerateDebugInformation>true</GenerateDebugInformation>\n"
        "    </Link>\n"
        "  </ItemDefinitionGroup>\n"
        "\n"
        "  <ItemDefinitionGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\">\n"
        "    <ClCompile>\n"
        "      <WarningLevel>Level3</WarningLevel>\n"
        "      <FunctionLevelLinking>true</FunctionLevelLinking>\n"
        "      <IntrinsicFunctions>true</IntrinsicFunctions>\n"
        "      <SDLCheck>true</SDLCheck>\n"
        "      <PreprocessorDefinitions>NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>\n"
        "      <ConformanceMode>true</ConformanceMode>\n"
        "      <LanguageStandard>stdcpp23</LanguageStandard>\n"
        "      <LanguageStandard_C>stdclatest</LanguageStandard_C>\n"
        "    </ClCompile>\n"
        "    <Link>\n"
        "      <SubSystem>Console</SubSystem>\n"
        "      <GenerateDebugInformation>true</GenerateDebugInformation>\n"
        "    </Link>\n"
        "  </ItemDefinitionGroup>\n"
        "\n"
        "  <ItemGroup>\n"
        "    <ClInclude Include=\"Include\\%%NAME%%\\Include.h\" />\n"
        "    <ClInclude Include=\"Include\\%%NAME%%\\Macros.h\" />\n"
        "  </ItemGroup>\n"
        "  <ItemGroup>\n"
        "    <ClCompile Include=\"Source\\%%NAME%%\\Source.cpp\" />\n"
        "  </ItemGroup>\n"
        "  <ItemGroup>\n"
        "    <None Include=\"%%NAME%%.def\" />\n"
        "  </ItemGroup>\n"
        "\n"
        "  <Import Project=\"$(VCTargetsPath)\\Microsoft.Cpp.targets\" />\n"
        "  <ImportGroup Label=\"ExtensionTargets\" />\n"
        "\n"
        "</Project>\n"
        "\n"
        ;
    return data;
}

static const char* DEF_TEMPLATE()
{
    static const char data[] =
        "LIBRARY %%NAME%%\n"
        "\n"
        "EXPORTS\n"
        "    ; Add all four symbols for every hook:\n"
        "    ;\n"
        "    ;   <HookName>           - the hook function\n"
        "    ;   <HookName>_End       - the end sentinel immediately after it\n"
        "    ;   g_<hookName>Data     - hook-data global (value, not pointer)\n"
        "    ;   g_p<HookName>OrigFn  - original-function pointer slot\n"
        "    ;\n"
        "    ; Example:\n"
        "    ;   GetCoins_Hook\n"
        "    ;   GetCoins_Hook_End\n"
        "    ;   g_getCoinsData\n"
        "    ;   g_pGetCoinsOrigFn\n"
        "\n"
        ;
    return data;
}

static const char* MACROS_H_TEMPLATE()
{
    static const char data[] =
        "#pragma once\n"
        "// =============================================================================\n"
        "//  %%NAME%%/Macros.h\n"
        "//\n"
        "//  Three macros covering every authoring concern for a shellcode hook:\n"
        "//\n"
        "//    HOOK_BEGIN   open a hook block  (set segments + disable compiler helpers)\n"
        "//    HOOK_END     close a hook block (restore all settings)\n"
        "//    HOOK_EXPORT  extern \"C\" __declspec(dllexport)\n"
        "//\n"
        "//  See README.md for the rationale behind each pragma.\n"
        "// =============================================================================\n"
        "\n"
        "// -----------------------------------------------------------------------------\n"
        "//  HOOK_BEGIN\n"
        "//\n"
        "//  1. Routes code / data / BSS into the .hook section family so the linker\n"
        "//     merges them into one contiguous byte range via /MERGE:.hookd=.hook etc.\n"
        "//  2. Disables the three compiler features that emit CRT helper calls:\n"
        "//       optimize       off  -- no inlining / reordering across the boundary\n"
        "//       runtime_checks off  -- suppresses /RTC helpers (__RTC_CheckEsp etc.)\n"
        "//       check_stack    off  -- suppresses __chkstk stack probes\n"
        "//\n"
        "//  _Pragma() is used because #pragma is not permitted inside a #define.\n"
        "//  MSVC supports _Pragma since VS 2019 16.6.\n"
        "// -----------------------------------------------------------------------------\n"
        "#define HOOK_BEGIN                                    \\\n"
        "    _Pragma(\"code_seg(\\\".hook\\\")\")                    \\\n"
        "    _Pragma(\"data_seg(\\\".hookd\\\")\")                   \\\n"
        "    _Pragma(\"bss_seg(\\\".hookb\\\")\")                    \\\n"
        "    _Pragma(\"optimize(\\\"\\\", off)\")                    \\\n"
        "    _Pragma(\"runtime_checks(\\\"\\\", off)\")              \\\n"
        "    _Pragma(\"check_stack(off)\")\n"
        "\n"
        "// -----------------------------------------------------------------------------\n"
        "//  HOOK_END\n"
        "//\n"
        "//  Restores everything changed by HOOK_BEGIN.\n"
        "//  Place AFTER the end sentinel, not before it.\n"
        "// -----------------------------------------------------------------------------\n"
        "#define HOOK_END                                      \\\n"
        "    _Pragma(\"check_stack()\")                          \\\n"
        "    _Pragma(\"runtime_checks(\\\"\\\", restore)\")          \\\n"
        "    _Pragma(\"optimize(\\\"\\\", on)\")                     \\\n"
        "    _Pragma(\"code_seg()\")                             \\\n"
        "    _Pragma(\"data_seg()\")                             \\\n"
        "    _Pragma(\"bss_seg()\")\n"
        "\n"
        "// -----------------------------------------------------------------------------\n"
        "//  HOOK_EXPORT\n"
        "//\n"
        "//  extern \"C\" __declspec(dllexport)\n"
        "//\n"
        "//  Apply to every global and function that LoadHook must locate via\n"
        "//  GetProcAddress.  Each symbol must also appear in the .def EXPORTS.\n"
        "// -----------------------------------------------------------------------------\n"
        "#define HOOK_EXPORT extern \"C\" __declspec(dllexport)\n"
        "\n"
        ;
    return data;
}

static const char* INCLUDE_H_TEMPLATE()
{
    static const char data[] =
        "#pragma once\n"
        "// =============================================================================\n"
        "//  %%NAME%%/Include.h  --  master include for the %%NAME%% shellcode DLL\n"
        "// =============================================================================\n"
        "\n"
        "#include <%%NAME%%/Macros.h>\n"
        "\n"
        ;
    return data;
}

static const char* SOURCE_CPP_TEMPLATE()
{
    static const char data[] =
        "// =============================================================================\n"
        "//  %%NAME%% -- x86 shellcode DLL\n"
        "//\n"
        "//  Compiled as a 32-bit DLL with no CRT.  Hook functions are located by\n"
        "//  exported symbol name, rebased, and injected by ShellcodeDLL86::LoadHook().\n"
        "//\n"
        "//  HOW TO ADD A NEW HOOK\n"
        "//  ---------------------\n"
        "//  1.  Define a hook-data struct below.\n"
        "//  2.  Open HOOK_BEGIN.\n"
        "//  3.  Declare the data global and orig-fn pointer with HOOK_EXPORT.\n"
        "//  4.  Write the hook function (HOOK_EXPORT, __fastcall, correct ret N).\n"
        "//  5.  Add the end sentinel immediately after -- nothing between them.\n"
        "//  6.  Close with HOOK_END (after the sentinel).\n"
        "//  7.  Add all four symbols to %%NAME%%.def EXPORTS.\n"
        "// =============================================================================\n"
        "\n"
        "#include <Windows.h>\n"
        "#include <cstdint>\n"
        "#include <%%NAME%%/Include.h>\n"
        "\n"
        "// =============================================================================\n"
        "//  Hook data structs\n"
        "//\n"
        "//  Fields are populated remotely by ShellcodeDLL86 before the hook fires.\n"
        "//  Always hold by VALUE -- a pointer requires a second remote dereference\n"
        "//  that the injected shellcode cannot perform.\n"
        "// =============================================================================\n"
        "\n"
        "struct MyHookData\n"
        "{\n"
        "    int exampleField = 0;\n"
        "};\n"
        "\n"
        "\n"
        "// =============================================================================\n"
        "//  MyHook  --  rename and implement for your target function\n"
        "// =============================================================================\n"
        "\n"
        "HOOK_BEGIN\n"
        "\n"
        "//  Hook-data global.  Populated by LoadHook via WriteField before injection.\n"
        "HOOK_EXPORT MyHookData g_myHookData    = {};\n"
        "\n"
        "//  Original-function pointer.  Patched by HookPrepatched / LoadHook.\n"
        "HOOK_EXPORT void*      g_pMyHookOrigFn = nullptr;\n"
        "\n"
        "//  Hook function.\n"
        "//\n"
        "//  Calling convention:\n"
        "//    __fastcall is a drop-in for __thiscall -- both pass arg0 in ECX.\n"
        "//    Declare the same stack params as the original to emit the correct\n"
        "//    ret N and keep ESP balanced in the caller.\n"
        "//\n"
        "HOOK_EXPORT\n"
        "int __fastcall MyHook(void* thisPtr, int /*edx*/, int a2, int a3)\n"
        "{\n"
        "    typedef int(__thiscall* OrigFn)(void*, int, int);\n"
        "    const auto original = reinterpret_cast<OrigFn>(g_pMyHookOrigFn);\n"
        "\n"
        "    // TODO: implement hook logic using g_myHookData fields.\n"
        "    return original(thisPtr, a2, a3);\n"
        "}\n"
        "\n"
        "//  End sentinel -- must be the very next symbol after MyHook.\n"
        "//  HOOK_END comes after this line.\n"
        "HOOK_EXPORT void MyHook_End() {}\n"
        "\n"
        "HOOK_END\n"
        "\n"
        "\n"
        "// =============================================================================\n"
        "//  DllMain\n"
        "// =============================================================================\n"
        "\n"
        "BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) { return TRUE; }\n"
        "\n"
        ;
    return data;
}

// ── Entry point ───────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::fprintf(stderr,
            "Usage: create_shellcode_project <ProjectName> [OutputDir]\n"
            "\n"
            "  ProjectName  Name for the new shellcode DLL project\n"
            "  OutputDir    Directory to create the project in (default: .)\n"
            "\n"
            "Example:\n"
            "  create_shellcode_project GetCoins ./Projects\n");
        return 1;
    }

    const std::string project_name = argv[1];
    const fs::path    output_base = (argc >= 3) ? fs::path(argv[2]) : fs::path(".");
    const fs::path    project_dir = output_base / project_name;

    // Validate: letters, digits, underscores only
    for (char c : project_name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') {
            std::fprintf(stderr,
                "error: ProjectName must contain only letters, digits, and underscores.\n");
            return 1;
        }
    }

    if (fs::exists(project_dir)) {
        std::fprintf(stderr, "error: directory already exists: %s\n",
            fs::absolute(project_dir).string().c_str());
        return 1;
    }

    try {
        const std::string guid = make_guid();

        std::printf("\nScaffolding: %s\n", project_name.c_str());
        std::printf("Directory:   %s\n\n",
            fs::absolute(project_dir).string().c_str());

        write_file(project_dir / (project_name + ".vcxproj"),
            fill(VCXPROJ_TEMPLATE(), project_name, guid));

        write_file(project_dir / (project_name + ".def"),
            fill(DEF_TEMPLATE(), project_name));

        write_file(project_dir / "Include" / project_name / "Macros.h",
            fill(MACROS_H_TEMPLATE(), project_name));

        write_file(project_dir / "Include" / project_name / "Include.h",
            fill(INCLUDE_H_TEMPLATE(), project_name));

        write_file(project_dir / "Source" / project_name / "Source.cpp",
            fill(SOURCE_CPP_TEMPLATE(), project_name));

        std::printf(
            "\nDone.  Next steps:\n"
            "  1. Add %s.vcxproj to your Visual Studio solution.\n"
            "  2. Rename MyHook / MyHookData / g_myHookData / g_pMyHookOrigFn.\n"
            "  3. Add all four symbols to %s.def EXPORTS.\n"
            "  4. Build Win32 Release  ->  Bin\\Win32\\Release\\%s.dll\n\n",
            project_name.c_str(),
            project_name.c_str(),
            project_name.c_str());
    }
    catch (const std::exception& ex) {
        std::fprintf(stderr, "error: %s\n", ex.what());
        return 1;
    }

    return 0;
}