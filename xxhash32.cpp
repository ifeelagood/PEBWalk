#include "xxhash32.h"


uint32_t xxh32_runtime(const char* input, const uint32_t seed)
{
    size_t N = std::char_traits<char>::length(input);
    
    return xxhash32::xxh32(input, N+1, seed);
}
