add_library(cbmpc_protocol OBJECT "")

if(IS_WASM)
  # Integra: emcc cannot build CMake's precompiled header; force-include the same header instead.
  target_compile_options(cbmpc_protocol PUBLIC "SHELL:-include ${ROOT_DIR}/include-internal/cbmpc/internal/protocol/mpc_job.h")
else()
  target_precompile_headers(cbmpc_protocol PUBLIC "${ROOT_DIR}/include-internal/cbmpc/internal/protocol/mpc_job.h")
endif()

target_sources(cbmpc_protocol  PRIVATE
  int_commitment.cpp

  mpc_job.cpp

  agree_random.cpp
  ot.cpp

  pve_base.cpp
  pve.cpp
  pve_batch.cpp
  pve_ac.cpp

  ec_dkg.cpp
  ecdsa_2p.cpp
  ecdsa_mp.cpp
  schnorr_2p.cpp
  schnorr_mp.cpp
  eddsa.cpp

  hd_tree_bip32.cpp
  hd_keyset_ecdsa_2p.cpp
  hd_keyset_eddsa_2p.cpp
)

target_link_libraries(cbmpc_protocol cbmpc_zk)
