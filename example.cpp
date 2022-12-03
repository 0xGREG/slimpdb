#include <iostream>
#include <vector>
#include <fstream>
#include <Windows.h>

#include "pdb.hpp"

std::vector<char> read_file(std::string file_name)
{
	std::ifstream file_stream(file_name, std::ios::binary | std::ios::ate);
	std::streamsize stream_size = file_stream.tellg();
	file_stream.seekg(0, std::ios::beg);

	std::vector<char> buffer(stream_size);
	file_stream.read(buffer.data(), stream_size);

	return buffer;
}

int main()
{
	// read ntoskrnl exe and pdb file
	
	auto ntoskrnl_exe = read_file(R"(C:\Windows\System32\ntoskrnl.exe)");
	auto ntoskrnl_pdb = read_file(R"(C:\Windows\ntoskrnl.pdb)");

	// get ntoskrnl data

	auto ntoskrnl_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(ntoskrnl_exe.data());
	auto ntoskrnl_nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(ntoskrnl_exe.data() + ntoskrnl_dos->e_lfanew);
	auto ntoskrnl_sections = IMAGE_FIRST_SECTION(ntoskrnl_nt);

	// parse pdb file

	pdb::stream_data_t symbols{};

	pdb::parse_buffer(ntoskrnl_pdb.data(), &symbols);
	
	// iterate symbols

	auto symbols_current = reinterpret_cast<uintptr_t>(symbols.buffer);

	while (symbols_current != (reinterpret_cast<uintptr_t>(symbols.buffer) + symbols.size))
	{
		const auto it = reinterpret_cast<pdb::pubsym32_t*>(symbols_current);
		symbols_current += it->reclen + 2ull;

		if (it->rectyp != pdb::S_PUB32)
			continue;

		if (strcmp(it->name, "MiGetPteAddress") != 0)
			continue;

		// get function info

		printf("S_PUB32: [%04X:%08X], flags: %08X, name: %s\n", it->seg, it->off, it->pubsymflags, it->name);

		std::cout << "symbol section: " << ntoskrnl_sections[it->seg - 1].Name << std::endl;
		std::cout << "symbol rva: " << std::hex << (ntoskrnl_sections[it->seg - 1].VirtualAddress + it->off) << std::dec << std::endl;
	}

	// free pdb data

	pdb::free_memory(symbols.buffer);

	// done

	return 0;
}
