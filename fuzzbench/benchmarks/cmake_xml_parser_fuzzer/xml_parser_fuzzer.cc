/* Local harness for CMake xml_parser_fuzzer.
 *
 * This version is identical to the upstream harness except that it does *not*
 * return a non-zero value when parsing fails. Returning 1 on parse failure
 * causes libFuzzer to treat every invalid XML as a crash
 * (assert(Res == 0) in FuzzerLoop.cpp). For coverage experiments we want
 * parse errors to be non-fatal, so we ignore the return value and always
 * return 0.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "cmXMLParser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  char test_file[] = "libfuzzer.xml";

  FILE* fp = fopen(test_file, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  cmXMLParser parser;
  // Treat parse failures as normal behavior, not crashes.
  (void)parser.ParseFile(test_file);

  remove(test_file);
  return 0;
}

