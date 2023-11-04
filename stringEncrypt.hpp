
#pragma once
#include <cstdint>

#include "Random.hpp"

#pragma warning(disable: 4307)
namespace Obfuscation::String
{
	template <uint32_t Size, uint32_t Counter>
	struct ObfuscatedString
	{
		static constexpr std::array<uint8_t, Size> XOR = uniform_distribution<uint8_t, Size, Counter>(0, 255);
		std::array<char, Size> Encrypted;

		static __forceinline constexpr char Encrypt(uint32_t Idx, char C) {
			return C ^ XOR[Idx];
		}

		template <size_t... Idx>
		__forceinline constexpr ObfuscatedString(const char* Str, std::index_sequence<Idx...>) :
			Encrypted({ Encrypt(Idx, Str[Idx])... }) { }

		__forceinline const char* Decrypt() {
			for (uint32_t x = 0; x < Size; x++)
				Encrypted[x] ^= XOR[x];

			return Encrypted.data();
		}
	};
}

#pragma warning(disable: 4307)
namespace OtherObfuscation::String
{
	template <uint32_t Size, uint32_t Counter>
	struct ObfuscatedString
	{
		static constexpr std::array<uint8_t, Size> XOR = uniform_distribution<uint8_t, Size, Counter>(0, 255);
		std::array<char, Size> Encrypted;

		static __forceinline constexpr char Encrypt(uint32_t Idx, char C) {
			return C ^ XOR[Idx];
		}

		template <size_t... Idx>
		__forceinline constexpr ObfuscatedString(const char* Str, std::index_sequence<Idx...>) :
			Encrypted({ Encrypt(Idx, Str[Idx])... }) { }

		__forceinline std::string Decrypt() {
			for (uint32_t x = 0; x < Size; x++)
				Encrypted[x] ^= XOR[x];

			return std::string(Encrypted.data(), Size);
		}
	};
}

#define OBFUSCATE_STR(s) (Obfuscation::String::ObfuscatedString<sizeof(s), __COUNTER__>(s, std::make_index_sequence<sizeof(s)>()).Decrypt())
#define OBFUSCATE_OTHER(s) (OtherObfuscation::String::ObfuscatedString<sizeof(s), __COUNTER__>(s, std::make_index_sequence<sizeof(s)>()).Decrypt())