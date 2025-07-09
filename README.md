# DuckDB JWT Extension

This extension provides JWT (JSON Web Token) functionality for [DuckDB](https://duckdb.org/), allowing you to decode and work with JWT tokens directly in your SQL queries.

## Features

- `jwt_decode_payload(token)`: Decodes the payload part of a JWT token and returns it as a JSON string
- Base64 URL-safe decoding for JWT token components

## Use Cases

- Analyzing JWT tokens in your data
- Extracting claims from authentication tokens
- Debugging JWT-based authentication systems
- Working with JWT tokens in data pipelines

## Installation

### From Source

This extension can be built from source following these steps:

```sh
# Clone the repository
git clone https://github.com/yourusername/duckdb_jwt.git
cd duckdb_jwt

# Build the extension
make
```

The main binaries that will be built are:

```sh
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/jwt/jwt.duckdb_extension
```

- `duckdb` is the binary for the DuckDB shell with the extension code automatically loaded
- `unittest` is the test runner of DuckDB with the extension linked
- `jwt.duckdb_extension` is the loadable extension binary

### Using Package Manager

If the extension is published to DuckDB's extension repository:

```sql
INSTALL jwt;
LOAD jwt;
```

## Usage Examples

### Decode JWT Payload

```sql
-- Decode a JWT token payload
SELECT jwt_decode_payload('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c') AS payload;
```

Output:

```
┌───────────────────────────────────────────────────────┐
│                       payload                         │
│                       varchar                         │
├───────────────────────────────────────────────────────┤
│ {"sub":"1234567890","name":"John Doe","iat":1516239022} │
└───────────────────────────────────────────────────────┘
```

### Extract Specific Claims

You can combine with DuckDB's JSON functionality to extract specific claims:

```sql
-- Extract the 'sub' claim from a JWT token
SELECT 
  json_extract(
    jwt_decode_payload('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'),
    '$.sub'
  ) AS subject;
```

## Running Tests

To run the SQL tests for this extension:

```sh
make test
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- This extension is based on the [DuckDB extension template](https://github.com/duckdb/extension-template)
- Thanks to the DuckDB team for providing the extension framework
