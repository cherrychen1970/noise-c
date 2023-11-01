# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

add_subdirectory(../src noise)
# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("noise-echo")

add_definitions(
    -D_CRT_SECURE_NO_WARNINGS
)

include_directories(
  "../include"
  "./"
  "./protocol"
  ./echo/common
)

file(GLOB CLIENT_SRC_FILES
    ./echo/echo-client/*.c
	#./echo/common/*.c
	)

add_executable (noise-echo-client ${CLIENT_SRC_FILES})

set(LINK_LIBS crypt32 ws2_32 noise-protocol noise-crypto noise-ref noise-protobuf)

target_link_libraries(noise-echo-client ${LINK_LIBS})

# TODO: Add tests and install targets if needed.
