#include "felix86/gui.h"
#include "felix86/loader/loader.h"
#include "felix86/common/version.h"
#include "felix86/common/log.h"
#include <stdio.h>
#include <argp.h>

const char* argp_program_version = "felix86 " FELIX86_VERSION;
const char* argp_program_bug_address = "<https://github.com/OFFTKP/felix86/issues>";

static char doc[] = "felix86 - a userspace x86_64 emulator";
static char args_doc[] = "BINARY [ARGS...]";

static struct argp_option options[] = {
  { "verbose", 'v', 0, 0, "Produce verbose output" },
  { "verify", 'V', 0, 0, "Verify each instruction, only works on x86-64 host" },
  { "quiet", 'q', 0, 0, "Don't produce any output" },
  { "interpreter", 'i', 0, 0, "Run in interpreter mode" },
  { "host-envs", 'e', 0, 0, "Pass host environment variables to the guest" },
  { "print-blocks", 'p', 0, 0, "Print basic blocks as they compile" },
  { "dont-optimize", 'O', 0, 0, "Don't run IR optimizations" },
  { 0 }
};

static error_t parse_opt (int key, char* arg, struct argp_state* state)
{
    loader_config_t* config = state->input;

    if (key == ARGP_KEY_ARG) {
        // This is one of the guest executable arguments
        if (config->argc == 255) {
            printf("Too many guest arguments\n");
            argp_usage(state);
        }

        config->argv[config->argc++] = arg;
        return 0;
    }

    switch (key) {
        case 'V': {
#ifdef __x86_64__
            config->verify = true;
#else
            WARN("Verification only works on x86-64 hosts");
            return ARGP_ERR_UNKNOWN;
#endif
            break;
        }
        case 'v': {
            enable_verbose();
            break;
        }
        case 'q': {
            disable_logging();
            break;
        }
        case 'e': {
            config->use_host_envs = true;
            break;
        }
        case 'p': {
            config->print_blocks = true;
            break;
        }
        case 'i': {
            config->use_interpreter = true;
            break;
        }
        case 'O': {
            config->dont_optimize = true;
            break;
        }
        case ARGP_KEY_END: {
            break;
        }

        default: {
            return ARGP_ERR_UNKNOWN;
        }
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char* argv[]) {
    loader_config_t config = {0};
    config.use_interpreter = false;

    argp_parse(&argp, argc, argv, 0, 0, &config);

    if (argc == 1) {
        felix86_gui();
    } else {
        loader_run_elf(&config);
    }

    return 0;
}