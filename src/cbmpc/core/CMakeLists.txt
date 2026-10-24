add_library(cbmpc_core OBJECT "")

# Link OpenSSL before precompiled headers to ensure headers are available
link_openssl(cbmpc_core)

if(IS_WASM)
  # Integra: emcc cannot build CMake's precompiled header; force-include the same header instead.
  target_compile_options(cbmpc_core PUBLIC "SHELL:-include ${ROOT_DIR}/include/cbmpc/core/precompiled.h")
else()
  target_precompile_headers(cbmpc_core PUBLIC "${ROOT_DIR}/include/cbmpc/core/precompiled.h")
endif()

target_sources(cbmpc_core PRIVATE
  buf.cpp
  buf128.cpp
  buf256.cpp
  convert.cpp
  error.cpp
  strext.cpp
)
