add_library(cbmpc_crypto OBJECT "")

# For secp256k1
target_include_directories(cbmpc_crypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../vendors)

if(CBMPC_TEST_RNG)
  target_sources(cbmpc_crypto PRIVATE test_rng.cpp)
  target_compile_definitions(cbmpc_crypto PUBLIC CBMPC_TEST_RNG)
  message(WARNING "CBMPC_TEST_RNG=ON — deterministic test RNG is COMPILED IN. Never ship this build.")
endif()

target_sources(cbmpc_crypto  PRIVATE
  ec25519_core.cpp

  base.cpp
  base_bn.cpp
  base_mod.cpp
  base_ec_core.cpp
  base_ecc.cpp
  base_eddsa.cpp
  base_ecc_secp256k1.cpp
  base_hash.cpp
  base_rsa.cpp
  base_paillier.cpp
  base_rsa_oaep.cpp
  base_pki.cpp

  drbg.cpp
  ro.cpp
  elgamal.cpp

  lagrange.cpp
  secret_sharing.cpp

  tdh2.cpp
)

target_link_libraries(cbmpc_crypto cbmpc_core)
