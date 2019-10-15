#include <windows.h>
#include <memoryapi.h>
#include <string>
#include <cstdint>
#include <thread>
#include <chrono>

bool __stdcall PatchFunction( HMODULE module_start )
{
	AllocConsole( );
	SetConsoleTitleA( "Season Pass Unlocker" );

	const auto exit_procedure = [ &module_start ]( )
	{
		fclose( stdin );
		fclose( stdout );
		FreeConsole( );
		PostMessage( GetConsoleWindow( ), WM_CLOSE, 0, 0 );
		FreeLibraryAndExitThread( module_start, EXIT_SUCCESS );
	};

	freopen_s( reinterpret_cast< FILE** >( stdin ), "CONIN$", "r", stdin );
	freopen_s( reinterpret_cast< FILE** >( stdout ), "CONOUT$", "w", stdout );

	auto uplay_r1 = GetModuleHandleA( "uplay_r1_loader64.dll" );

	while ( !uplay_r1 )
		uplay_r1 = GetModuleHandleA( "uplay_r1_loader64.dll" );

	std::printf( "	%s -> uplay_r1_loader64.dll found at 0x%p\n", __FUNCTION__, uplay_r1 );

	const auto is_owned = GetProcAddress( uplay_r1, "UPLAY_USER_IsOwned" );

	if ( is_owned == 0 )
	{
		std::printf( "	%s -> couldn't get UPLAY_USER_IsOwned procedure\n", __FUNCTION__ );
		std::this_thread::sleep_for( std::chrono::seconds( 5 ) );
		exit_procedure( );
		return false;
	}

	std::printf( "	%s -> UPLAY_USER_IsOwned found at 0x%p\n", __FUNCTION__, is_owned );

	const auto is_owned_0 = reinterpret_cast<PVOID>( std::uintptr_t( is_owned ) + 0x7131 ); // static offset off the initial export cause im lazy.

	std::printf( "	%s -> UPLAY_USER_IsOwned_0 found at 0x%p\n", __FUNCTION__, is_owned_0 );

	const auto spaces_needed = std::string( strlen( __FUNCTION__ ), ' ' );

	constexpr std::uint8_t shell_code[ ] = { 0xB9, 0x01, 0x00, 0x00, 0x00 };

	const auto wanted_bytes = std::uintptr_t(is_owned_0) + 0xD;

	std::printf( "\n	%s -> UPLAY_USER_IsOwned_0 + 0xD 7 bytes: \n	    %s", __FUNCTION__, spaces_needed.c_str( ) );

	for ( auto current = 0; current < 7; current++ )
		std::printf( "0x%x ", *reinterpret_cast< std::uint8_t* >( std::uintptr_t( wanted_bytes ) + current ) );

	ULONG old_protection = 0;

	VirtualProtect( reinterpret_cast< LPVOID >( wanted_bytes ), sizeof( shell_code ), PAGE_READWRITE, &old_protection );

	for ( auto current = 0; current < sizeof( shell_code ); current++ )
		*reinterpret_cast< std::uint8_t* >( wanted_bytes + current ) = shell_code[ current ];

	VirtualProtect( reinterpret_cast< LPVOID >( wanted_bytes ), sizeof( shell_code ), old_protection, &old_protection );

	std::printf( "\n	%s -> UPLAY_USER_IsOwned_0 + 0xD 7 bytes: \n  	    %s", __FUNCTION__, spaces_needed.c_str( ) );

	for ( auto current = 0; current < 7; current++ )
		std::printf( "0x%x ", *reinterpret_cast< std::uint8_t* >( std::uintptr_t( wanted_bytes ) + current ) );

	while ( !GetAsyncKeyState( VK_END ) )
		std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );

	exit_procedure( );

	return true;
}

bool __stdcall DllMain( HMODULE module_start, std::uint32_t call_reason, void* reserved )
{
	if ( call_reason != DLL_PROCESS_ATTACH )
		return false;
	
	if ( const auto handle = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(PatchFunction), module_start, 0, nullptr); handle != NULL)
		CloseHandle(handle);

	return true;
}
