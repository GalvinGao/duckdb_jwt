#define DUCKDB_EXTENSION_MAIN

#include "duckdb.hpp"
#include "duckdb/main/extension_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/common/string_util.hpp"
#include "jwt_extension.hpp"
#include <string>
#include <vector>
#include <stdexcept>
#include "mbedtls/base64.h"

using namespace duckdb;

namespace jwt_extension {

// Base64 URL-safe to standard Base64 conversion
std::string base64url_to_base64(const std::string &base64url) {
	std::string base64 = base64url;
	// Replace URL-safe characters with standard Base64 characters
	StringUtil::Replace(base64, "-", "+");
	StringUtil::Replace(base64, "_", "/");

	// Add padding if needed
	int padding = (4 - (base64.length() % 4)) % 4;
	base64.append(padding, '=');

	return base64;
}

// Base64 URL-safe decode function using mbedtls
std::string base64_url_decode(const std::string &encoded) {
	// Convert from base64url to standard base64
	std::string base64 = base64url_to_base64(encoded);

	// Get the required output buffer size
	size_t output_len = 0;
	int ret = mbedtls_base64_decode(nullptr, 0, &output_len, (const unsigned char *)base64.c_str(), base64.length());

	if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
		throw std::runtime_error("Failed to calculate base64 decoded size");
	}

	// Allocate buffer for decoded data
	std::vector<unsigned char> decoded(output_len);

	// Decode the base64 string
	ret = mbedtls_base64_decode(decoded.data(), decoded.size(), &output_len, (const unsigned char *)base64.c_str(),
	                            base64.length());

	if (ret != 0) {
		throw std::runtime_error("Invalid base64 character");
	}

	// Convert to string
	return std::string(reinterpret_cast<char *>(decoded.data()), output_len);
}

// JWT payload decoding function
static void jwt_decode_payload_function(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &jwt_vector = args.data[0];
	UnaryExecutor::Execute<string_t, string_t>(jwt_vector, result, args.size(), [&](string_t jwt_token) {
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
		} catch (const std::exception &e) {
			throw InvalidInputException("Failed to decode JWT payload: " + std::string(e.what()));
		}
	});
}

// Extension loading function
static void LoadInternal(DatabaseInstance &instance) {
	// Register the jwt_decode_payload function
	auto jwt_decode_payload_func =
	    ScalarFunction("jwt_decode_payload", {LogicalType::VARCHAR}, LogicalType::VARCHAR, jwt_decode_payload_function);

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

std::string JwtExtension::Version() const {
	return "v0.0.1";
}

} // namespace duckdb

extern "C" {
DUCKDB_EXTENSION_API void jwt_init(duckdb::DatabaseInstance &db) {
	jwt_extension::LoadInternal(db);
}

DUCKDB_EXTENSION_API const char *jwt_version() {
	return "v0.0.1";
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif
