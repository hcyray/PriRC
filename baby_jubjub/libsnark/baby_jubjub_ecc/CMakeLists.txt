#include_directories(.)


add_library(
  baby_jubjub_ecc
  STATIC
  prc.cpp
  pedersen_commitment.hpp

  baby_jubjub.hpp

)

target_link_libraries(
  baby_jubjub_ecc
  snark
)


#set_property(TARGET baby_jubjub_ecc PROPERTY POSITION_INDEPENDENT_CODE ON)

INSTALL(
TARGETS
baby_jubjub_ecc

DESTINATION lib
)
