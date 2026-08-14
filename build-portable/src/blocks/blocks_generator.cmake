file(READ "${INPUT_DAT_FILE}" DATA HEX)
string(REGEX REPLACE "[0-9a-fA-F][0-9a-fA-F]" "0x\\0," DATA "${DATA}")
if("${DATA}" STREQUAL "")
  # Empty .dat: emit a 1-byte placeholder so the array is valid C.
  # _len is 0 so consumers know there is no real data.
  file(WRITE "${OUTPUT_C_SOURCE}" "
#include <stddef.h>
const unsigned char ${BLOB_NAME}[]={ 0x00 };
const size_t ${BLOB_NAME}_len = 0;
"
  )
else()
  file(WRITE "${OUTPUT_C_SOURCE}" "
#include <stddef.h>
const unsigned char ${BLOB_NAME}[]={
  ${DATA}
};
const size_t ${BLOB_NAME}_len = sizeof(${BLOB_NAME});
"
  )
endif()
