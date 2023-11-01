# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("noise-c")

include_directories(
  "./include"
  "./src"
  "./src/protocol"
)

# Add source to this project's executable.
add_library (noise-c 
	"./src/protocol/cipherstate.c" 
	"./src/protocol/dhstate.c"
	"./src/protocol/errors.c"
	"./src/protocol/handshakestate.c"
	"./src/protocol/hashstate.c"
	"./src/protocol/internal.c"
	"./src/protocol/names.c"
	"./src/protocol/patterns.c"
	"./src/protocol/randstate.c"
	"./src/protocol/signstate.c"
	"./src/protocol/symmetricstate.c"
	"./src/protocol/util.c"
	"./src/backend/ref/hash-blake2s.c"
	"./src/crypto/blake2/blake2s.c"
  "./src/backend/ref/cipher-aesgcm.c"
  "./src/protocol/rand_os.c"
	"./src/backend/ref/cipher-aesgcm.c"
	"./src/backend/ref/cipher-chachapoly.c"
  "./src/backend/ref/dh-curve25519.c"
	"./src/backend/ref/hash-blake2b.c"
	"./src/backend/ref/hash-sha256.c"
	"./src/backend/ref/hash-sha512.c"
	"./src/backend/ref/sign-ed25519.c"
	"./src/crypto/aes/rijndael-alg-fst.c"
	"./src/crypto/blake2/blake2b.c"
	"./src/crypto/chacha/chacha.c"
	"./src/crypto/donna/poly1305-donna.c"
	"./src/crypto/ghash/ghash.c"
	"./src/crypto/newhope/crypto_stream_chacha20.c"
	"./src/crypto/newhope/crypto_stream_chacha20.h"
	"./src/crypto/sha2/sha256.c"
	"./src/crypto/sha2/sha512.c"
	"./src/crypto/ed25519/ed25519.c"
)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET noise-c PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
