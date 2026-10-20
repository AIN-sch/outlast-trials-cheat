#include <Windows.h>
#include <iostream>
#include <chrono>
#include <fstream>

#include "Generators/CppGenerator.h"
#include "Generators/MappingGenerator.h"
#include "Generators/IDAMappingGenerator.h"
#include "Generators/DumpspaceGenerator.h"

#include "Generators/Generator.h"

enum class EFortToastType : uint8
{
        Default                        = 0,
        Subdued                        = 1,
        Impactful                      = 2,
        EFortToastType_MAX             = 3,
};

/* In-game calls can fault, so each one is isolated. */
static void QueryGameNameCore()
{
	FString Name;
	FString Version;
	UEClass Kismet = ObjectArray::FindClassFast("KismetSystemLibrary");
	UEFunction GetGameName = Kismet.GetFunction("KismetSystemLibrary", "GetGameName");
	UEFunction GetEngineVersion = Kismet.GetFunction("KismetSystemLibrary", "GetEngineVersion");

	Kismet.ProcessEvent(GetGameName, &Name);
	Kismet.ProcessEvent(GetEngineVersion, &Version);

	Settings::Generator::GameName = Name.ToString();
	Settings::Generator::GameVersion = Version.ToString();
}

static void QueryGameNameGuarded()
{
	StageLog("enter GameName query");

	__try
	{
		QueryGameNameCore();
		StageLog("ok GameName query");
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		StageLog("CRASH GameName query");
	}
}

#define DEFINE_GENERATOR_GUARD(Name, Type)                     \
	static void Generate_##Name##_Guarded()                    \
	{                                                          \
		StageLog("enter Generate<" #Name ">");                 \
		__try                                                 \
		{                                                      \
			Generator::Generate<Type>();                       \
			StageLog("ok Generate<" #Name ">");                \
		}                                                      \
		__except (EXCEPTION_EXECUTE_HANDLER)                   \
		{                                                      \
			StageLog("CRASH Generate<" #Name ">");             \
		}                                                      \
	}

DEFINE_GENERATOR_GUARD(CppGenerator, CppGenerator)
DEFINE_GENERATOR_GUARD(MappingGenerator, MappingGenerator)
DEFINE_GENERATOR_GUARD(IDAMappingGenerator, IDAMappingGenerator)
DEFINE_GENERATOR_GUARD(DumpspaceGenerator, DumpspaceGenerator)


DWORD MainThread(HMODULE Module)
{
	AllocConsole();
	FILE* Dummy;
	freopen_s(&Dummy, "CONOUT$", "w", stderr);
	freopen_s(&Dummy, "CONIN$", "r", stdin);

	std::cerr << "Initializing [Dumper-7]\n";

	StageLog("=== main thread start ===");

	Settings::Config::Load();
	Settings::Config::DelayDumperStart();

	StageLog("config loaded");
	
	std::cerr << "Started Generation [Dumper-7]!\n";
	auto DumpStartTime = std::chrono::high_resolution_clock::now();

	Generator::InitEngineCore();
	Generator::InitInternal();

	if (Settings::Generator::GameName.empty() && Settings::Generator::GameVersion.empty())
	{
		// Only Possible in Main()
		QueryGameNameGuarded();
	}

	std::cerr << "GameName: " << Settings::Generator::GameName << "\n";
	std::cerr << "GameVersion: " << Settings::Generator::GameVersion << "\n\n";

	std::cerr << "FolderName: " << (Settings::Generator::GameVersion + '-' + Settings::Generator::GameName) << "\n\n";

	StageLog(("names resolved: GameName=" + Settings::Generator::GameName +
		" GameVersion=" + Settings::Generator::GameVersion).c_str());

	Generate_CppGenerator_Guarded();
	Generate_MappingGenerator_Guarded();
	Generate_IDAMappingGenerator_Guarded();
	Generate_DumpspaceGenerator_Guarded();

	StageLog("=== all generators finished ===");

	auto DumpFinishTime = std::chrono::high_resolution_clock::now();

	std::chrono::duration<double, std::milli> DumpTime = DumpFinishTime - DumpStartTime;

	std::cerr << "\n\nGenerating SDK took (" << DumpTime.count() << "ms)\n\n\n";

	std::cerr << "\n\nPress F6 to unload\n\n\n";

	while (true)
	{
		if (GetAsyncKeyState(VK_F6) & 1)
		{
			fclose(stderr);
			if (Dummy) 
			{
				fclose(Dummy);
			}
			FreeConsole();

			FreeLibraryAndExitThread(Module, 0);
		}

		Sleep(100);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
		break;
	}

	return TRUE;
}
