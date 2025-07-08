#define DUCKDB_EXTENSION_MAIN

#include "duckdb.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/string_util.hpp"
#include "jwt_extension.hpp"
#include <string>
#include <vector>
#include <stdexcept>

using namespace duckdb;

namespace jwt_extension {

// Base64 URL-safe decoding table
static const int base64_url_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

// Base64 URL-safe decode function
std::string base64_url_decode(const std::string& encoded) {
    std::string input = encoded;

    // Add padding if needed
    int padding = (4 - (input.length() % 4)) % 4;
    input.append(padding, '=');

    std::string decoded;
    decoded.reserve(input.length() * 3 / 4);

    for (size_t i = 0; i < input.length(); i += 4) {
        int a = base64_url_decode_table[static_cast<unsigned char>(input[i])];
        int b = base64_url_decode_table[static_cast<unsigned char>(input[i + 1])];
        int c = base64_url_decode_table[static_cast<unsigned char>(input[i + 2])];
        int d = base64_url_decode_table[static_cast<unsigned char>(input[i + 3])];

        if (a == -1 || b == -1 || c == -1 || d == -1) {
            throw std::runtime_error("Invalid base64 character");
        }

        decoded += static_cast<char>((a << 2) | (b >> 4));
        if (input[i + 2] != '=') {
            decoded += static_cast<char>(((b & 0x0F) << 4) | (c >> 2));
        }
        if (input[i + 3] != '=') {
            decoded += static_cast<char>(((c & 0x03) << 6) | d);
        }
    }

    return decoded;
}

// JWT payload decoding function
static void jwt_decode_payload_function(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &jwt_vector = args.data[0];
    UnaryExecutor::Execute<string_t, string_t>(
        jwt_vector, result, args.size(),
        [&](string_t jwt_token) {
            std::string jwt_str = jwt_token.GetString();

            // Find the payload part (between first and second dot)
            size_t first_dot = jwt_str.find('.');
            if (first_dot == std::string::npos) {
                throw InvalidInputException("Invalid JWT format: no dots found");
            }

            size_t second_dot = jwt_str.find('.', first_dot + 1);
            if (second_dot == std::string::npos) {
                throw InvalidInputException("Invalid JWT format: only one dot found");
            }

            // Extract the payload part
            std::string payload_encoded = jwt_str.substr(first_dot + 1, second_dot - first_dot - 1);

            try {
                // Decode the base64 URL-safe encoded payload
                std::string payload_json = base64_url_decode(payload_encoded);
                return StringVector::AddString(result, payload_json);
            } catch (const std::exception& e) {
                throw InvalidInputException("Failed to decode JWT payload: " + std::string(e.what()));
            }
        });
}

// Extension loading function
static void LoadInternal(DatabaseInstance &instance) {
    // Register the jwt_decode_payload function
    auto jwt_decode_payload_func = ScalarFunction("jwt_decode_payload",
        {LogicalType::VARCHAR}, LogicalType::VARCHAR, jwt_decode_payload_function);

    ExtensionUtil::RegisterFunction(instance, jwt_decode_payload_func);
}

} // namespace jwt_extension

namespace duckdb {

void JwtExtension::Load(DuckDB &db) {
    jwt_extension::LoadInternal(*db.instance);
}

std::string JwtExtension::Name() {
    return "jwt";
}

std::string JwtExtension::Version() {
    return DuckDB::LibraryVersion();
}

} // namespace duckdb

extern "C" {
DUCKDB_EXTENSION_API void jwt_init(duckdb::DatabaseInstance &db) {
    jwt_extension::LoadInternal(db);
}

DUCKDB_EXTENSION_API const char *jwt_version() {
    return DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
