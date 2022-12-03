#pragma once
#include <cstdint>
#include <string.h>
#include <assert.h>

namespace pdb
{
	constexpr static char super_block_magic[] =
	{
		0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x20, 0x43, 0x2F,
		0x43, 0x2B, 0x2B, 0x20, 0x4D, 0x53, 0x46, 0x20, 0x37, 0x2E, 0x30, 0x30,
		0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00
	};

#pragma pack(push, 1)
	typedef struct _super_block_t
	{
		char file_magic[sizeof(super_block_magic)];
		uint32_t block_size;
		uint32_t free_block_map_block;
		uint32_t num_blocks;
		uint32_t num_directory_bytes;
		uint32_t unknown;
		uint32_t block_map_addr;
	} super_block_t;

	typedef struct _dbi_header_t
	{
		int32_t	version_signature;
		uint32_t version_header;
		uint32_t age;
		uint16_t global_stream_index;
		uint16_t build_number;
		uint16_t public_stream_index;
		uint16_t pdb_dll_version;
		uint16_t sym_record_stream;
		uint16_t pdb_dll_rbld;
		int32_t	mod_info_size;
		int32_t	section_contribution_size;
		int32_t	section_map_size;
		int32_t	source_info_size;
		int32_t	type_server_size;
		uint32_t mfc_type_server_index;
		int32_t	optional_dbg_header_size;
		int32_t	ec_substream_size;
		uint16_t flags;
		uint16_t machine;
		uint32_t padding;
	} dbi_header_t;

	typedef struct _pubsym32_t
	{
		std::uint16_t reclen;
		std::uint16_t rectyp;
		std::uint32_t pubsymflags;
		std::uint32_t off;
		std::uint16_t seg;
		char name[1];
	} pubsym32_t;

	typedef struct _stream_data_t
	{
		void* buffer;
		size_t size;
	} stream_data_t;

	enum { S_PUB32 = 0x110e };
#pragma pack(pop)

	void* alloc_memory(size_t size)
	{
		void* allocation = new uint8_t[size]();

		return allocation;
	}

	void free_memory(void* buffer)
	{
		delete[] reinterpret_cast<uint8_t*>(buffer);
	}

	void parse_buffer(void* pdb_data, stream_data_t* symbols)
	{
		// get super block

		const auto super_block = static_cast<super_block_t*>(pdb_data);
		
		// check if magic is valid
		
		assert(std::memcmp(super_block->file_magic, super_block_magic, sizeof(super_block_magic)) == 0);
		
		// get block size

		const auto block_size = super_block->block_size;

		// get stream directory size

		const auto dir_size = super_block->num_directory_bytes;

		// get directory block count and directory id array

		const auto dir_block_count = (dir_size + block_size - 1) / block_size;
		const auto dir_block_id_array = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(pdb_data) + block_size * super_block->block_map_addr);

		// allocate memory for stream directory

		void* dir_alloc = alloc_memory(dir_block_count * block_size);

		// copy directory blocks to allocation

		for (auto i = 0u; i < dir_block_count; ++i)
		{
			const auto dir_block = static_cast<uint8_t*>(pdb_data) + block_size * dir_block_id_array[i];

			std::memcpy(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(dir_alloc) + (i * block_size)), dir_block, block_size);
		}

		// prepapre stream data

		const auto stream_num = *reinterpret_cast<uint32_t*>(dir_alloc);
		const auto stream_array = reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(dir_alloc) + sizeof(uint32_t));
		auto block_id_current = reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(dir_alloc) + sizeof(uint32_t) + (stream_num * sizeof(uint32_t)));

		// prepare dbi header
		
		void* dbi_header = nullptr;

		// iterate streams

		for (auto i = 0u; i < stream_num; ++i)
		{
			const auto current_stream_size = stream_array[i];
			const auto current_stream_block_count = (current_stream_size + block_size - 1) / block_size;

			void* current_stream = alloc_memory(current_stream_block_count * block_size);

			for (auto j = 0u; j < current_stream_block_count; ++j)
			{
				//const auto block_id = block_id_array[j];
				const auto block_id = *block_id_current++;
				const auto block = static_cast<uint8_t*>(pdb_data) + block_size * block_id;

				std::memcpy(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(current_stream) + (j * block_size)), block, block_size);
			}

			// use stream or free it

			if (i == 3)
				dbi_header = current_stream;
			else if (dbi_header != nullptr && i == reinterpret_cast<dbi_header_t*>(dbi_header)->sym_record_stream)
			{
				*symbols = { current_stream, current_stream_size };
			}
			else
				free_memory(current_stream);
		}

		// free unneeded allocations
		
		free_memory(dbi_header);
		free_memory(dir_alloc);
	}
}
