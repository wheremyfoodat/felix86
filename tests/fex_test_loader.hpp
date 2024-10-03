#pragma once

#include <array>
#include <filesystem>
#include <vector>
#include "felix86/common/utility.hpp"
#include "felix86/common/x86.hpp"
#include "felix86/emulator.hpp"
#include <optional>

struct FEXTestLoader {
    FEXTestLoader(const std::filesystem::path& path);

    void Run();

    void Validate();

private:
    std::unique_ptr<Emulator> emulator {};
    std::vector<u8> buffer {};
    std::string json {};
    std::array<std::optional<u64>, 16> expected_gpr {};
    std::array<std::optional<XmmReg>, 16> expected_xmm {};
    std::vector<std::pair<u64, u64>> memory_mappings {};
};