#include "felix86/hle/filesystem.h"
#include <cstring>
#include <filesystem>

extern "C" int felix86_make_path_safe(char* buffer, u32 buffer_size, const char* path) {
    std::filesystem::path normal_path = std::filesystem::path(path).lexically_normal();
    std::string normal_path_str = normal_path.string();
    snprintf(buffer, buffer_size, "%s/%s", sandbox_path, normal_path_str.c_str());
    return normal_path.is_absolute();
}