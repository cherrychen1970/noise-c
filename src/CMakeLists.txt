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

add_definitions(
    -D_CRT_SECURE_NO_WARNINGS
    -DED25519_CUSTOMRANDOM
	-DED25519_CUSTOMHASH
)

include_directories(
  "../include"
  "./"
  "./protocol"
)

file(GLOB PROTOCOL_SRC_FILES
    ./protocol/*.c
	)

add_library (noise-protocol ${PROTOCOL_SRC_FILES})

file(GLOB CRYPTO_SRC_FILES
    ./crypto/aes/*.c
	./crypto/blake2/*.c
	./crypto/chacha/*.c
	#./crypto/curve448/*.c
	#./crypto/donna/*.c
	./crypto/ed25519/*.c
	./crypto/ghash/*.c
	./crypto/goldilocks/*.c
	#./crypto/newhope/*.c
	./crypto/sha2/*.c
	./crypto/donna/poly1305-donna.c
	)
add_library (noise-crypto ${CRYPTO_SRC_FILES})

file(GLOB REF_SRC_FILES
	./backend/ref/cipher-chachapoly.c
	./backend/ref/cipher-aesgcm.c
	./backend/ref/dh-curve25519.c
	./backend/ref/hash-blake2b.c
	./backend/ref/sign-ed25519.c
	./backend/ref/hash-sha512.c
	./backend/ref/hash-blake2s.c
	./backend/ref/hash-sha256.c
	)

add_library (noise-ref ${REF_SRC_FILES})


file(GLOB PROTOBUF_SRC_FILES
    ./protobufs/*.c
	)

add_library (noise-protobuf ${PROTOBUF_SRC_FILES})

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET noise-crypto PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
