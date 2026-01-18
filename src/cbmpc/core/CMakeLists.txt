add_library(cbmpc_core OBJECT "")

# Link OpenSSL before precompiled headers to ensure headers are available
link_openssl(cbmpc_core)

# Disable precompiled headers for WASM (emscripten doesn't support them well)
if(NOT IS_WASM)
  target_precompile_headers(cbmpc_core PUBLIC "precompiled.h")
endif()

target_sources(cbmpc_core PRIVATE
  buf.cpp
  buf128.cpp
  buf256.cpp
  convert.cpp
  error.cpp
  strext.cpp
  extended_uint.cpp
)
