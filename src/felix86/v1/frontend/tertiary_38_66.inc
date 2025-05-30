// x86_64 instruction handlers for the 0x66 0x0f 0x38 table, calls the equivalent ir_handle_* function in ir/emitter.h
// X(primary opcode, handler, decoding intricacy flag, whether this instruction has an immediate and its size)

X(0x00, error, NO_FLAG, NO_IMMEDIATE)
X(0x01, error, NO_FLAG, NO_IMMEDIATE)
X(0x02, error, NO_FLAG, NO_IMMEDIATE)
X(0x03, error, NO_FLAG, NO_IMMEDIATE)
X(0x04, error, NO_FLAG, NO_IMMEDIATE)
X(0x05, error, NO_FLAG, NO_IMMEDIATE)
X(0x06, error, NO_FLAG, NO_IMMEDIATE)
X(0x07, error, NO_FLAG, NO_IMMEDIATE)
X(0x08, error, NO_FLAG, NO_IMMEDIATE)
X(0x09, error, NO_FLAG, NO_IMMEDIATE)
X(0x0a, error, NO_FLAG, NO_IMMEDIATE)
X(0x0b, error, NO_FLAG, NO_IMMEDIATE)
X(0x0c, error, NO_FLAG, NO_IMMEDIATE)
X(0x0d, error, NO_FLAG, NO_IMMEDIATE)
X(0x0e, error, NO_FLAG, NO_IMMEDIATE)
X(0x0f, error, NO_FLAG, NO_IMMEDIATE)
X(0x10, error, NO_FLAG, NO_IMMEDIATE)
X(0x11, error, NO_FLAG, NO_IMMEDIATE)
X(0x12, error, NO_FLAG, NO_IMMEDIATE)
X(0x13, error, NO_FLAG, NO_IMMEDIATE)
X(0x14, error, NO_FLAG, NO_IMMEDIATE)
X(0x15, error, NO_FLAG, NO_IMMEDIATE)
X(0x16, error, NO_FLAG, NO_IMMEDIATE)
X(0x17, error, NO_FLAG, NO_IMMEDIATE)
X(0x18, error, NO_FLAG, NO_IMMEDIATE)
X(0x19, error, NO_FLAG, NO_IMMEDIATE)
X(0x1a, error, NO_FLAG, NO_IMMEDIATE)
X(0x1b, error, NO_FLAG, NO_IMMEDIATE)
X(0x1c, error, NO_FLAG, NO_IMMEDIATE)
X(0x1d, error, NO_FLAG, NO_IMMEDIATE)
X(0x1e, error, NO_FLAG, NO_IMMEDIATE)
X(0x1f, error, NO_FLAG, NO_IMMEDIATE)
X(0x20, error, NO_FLAG, NO_IMMEDIATE)
X(0x21, error, NO_FLAG, NO_IMMEDIATE)
X(0x22, error, NO_FLAG, NO_IMMEDIATE)
X(0x23, error, NO_FLAG, NO_IMMEDIATE)
X(0x24, error, NO_FLAG, NO_IMMEDIATE)
X(0x25, error, NO_FLAG, NO_IMMEDIATE)
X(0x26, error, NO_FLAG, NO_IMMEDIATE)
X(0x27, error, NO_FLAG, NO_IMMEDIATE)
X(0x28, error, NO_FLAG, NO_IMMEDIATE)
X(0x29, error, NO_FLAG, NO_IMMEDIATE)
X(0x2a, error, NO_FLAG, NO_IMMEDIATE)
X(0x2b, error, NO_FLAG, NO_IMMEDIATE)
X(0x2c, error, NO_FLAG, NO_IMMEDIATE)
X(0x2d, error, NO_FLAG, NO_IMMEDIATE)
X(0x2e, error, NO_FLAG, NO_IMMEDIATE)
X(0x2f, error, NO_FLAG, NO_IMMEDIATE)
X(0x30, error, NO_FLAG, NO_IMMEDIATE)
X(0x31, error, NO_FLAG, NO_IMMEDIATE)
X(0x32, error, NO_FLAG, NO_IMMEDIATE)
X(0x33, error, NO_FLAG, NO_IMMEDIATE)
X(0x34, error, NO_FLAG, NO_IMMEDIATE)
X(0x35, error, NO_FLAG, NO_IMMEDIATE)
X(0x36, error, NO_FLAG, NO_IMMEDIATE)
X(0x37, error, NO_FLAG, NO_IMMEDIATE)
X(0x38, error, NO_FLAG, NO_IMMEDIATE)
X(0x39, error, NO_FLAG, NO_IMMEDIATE)
X(0x3a, error, NO_FLAG, NO_IMMEDIATE)
X(0x3b, error, NO_FLAG, NO_IMMEDIATE)
X(0x3c, error, NO_FLAG, NO_IMMEDIATE)
X(0x3d, error, NO_FLAG, NO_IMMEDIATE)
X(0x3e, error, NO_FLAG, NO_IMMEDIATE)
X(0x3f, error, NO_FLAG, NO_IMMEDIATE)
X(0x40, error, NO_FLAG, NO_IMMEDIATE)
X(0x41, error, NO_FLAG, NO_IMMEDIATE)
X(0x42, error, NO_FLAG, NO_IMMEDIATE)
X(0x43, error, NO_FLAG, NO_IMMEDIATE)
X(0x44, error, NO_FLAG, NO_IMMEDIATE)
X(0x45, error, NO_FLAG, NO_IMMEDIATE)
X(0x46, error, NO_FLAG, NO_IMMEDIATE)
X(0x47, error, NO_FLAG, NO_IMMEDIATE)
X(0x48, error, NO_FLAG, NO_IMMEDIATE)
X(0x49, error, NO_FLAG, NO_IMMEDIATE)
X(0x4a, error, NO_FLAG, NO_IMMEDIATE)
X(0x4b, error, NO_FLAG, NO_IMMEDIATE)
X(0x4c, error, NO_FLAG, NO_IMMEDIATE)
X(0x4d, error, NO_FLAG, NO_IMMEDIATE)
X(0x4e, error, NO_FLAG, NO_IMMEDIATE)
X(0x4f, error, NO_FLAG, NO_IMMEDIATE)
X(0x50, error, NO_FLAG, NO_IMMEDIATE)
X(0x51, error, NO_FLAG, NO_IMMEDIATE)
X(0x52, error, NO_FLAG, NO_IMMEDIATE)
X(0x53, error, NO_FLAG, NO_IMMEDIATE)
X(0x54, error, NO_FLAG, NO_IMMEDIATE)
X(0x55, error, NO_FLAG, NO_IMMEDIATE)
X(0x56, error, NO_FLAG, NO_IMMEDIATE)
X(0x57, error, NO_FLAG, NO_IMMEDIATE)
X(0x58, error, NO_FLAG, NO_IMMEDIATE)
X(0x59, error, NO_FLAG, NO_IMMEDIATE)
X(0x5a, error, NO_FLAG, NO_IMMEDIATE)
X(0x5b, error, NO_FLAG, NO_IMMEDIATE)
X(0x5c, error, NO_FLAG, NO_IMMEDIATE)
X(0x5d, error, NO_FLAG, NO_IMMEDIATE)
X(0x5e, error, NO_FLAG, NO_IMMEDIATE)
X(0x5f, error, NO_FLAG, NO_IMMEDIATE)
X(0x60, error, NO_FLAG, NO_IMMEDIATE)
X(0x61, error, NO_FLAG, NO_IMMEDIATE)
X(0x62, error, NO_FLAG, NO_IMMEDIATE)
X(0x63, error, NO_FLAG, NO_IMMEDIATE)
X(0x64, error, NO_FLAG, NO_IMMEDIATE)
X(0x65, error, NO_FLAG, NO_IMMEDIATE)
X(0x66, error, NO_FLAG, NO_IMMEDIATE)
X(0x67, error, NO_FLAG, NO_IMMEDIATE)
X(0x68, error, NO_FLAG, NO_IMMEDIATE)
X(0x69, error, NO_FLAG, NO_IMMEDIATE)
X(0x6a, error, NO_FLAG, NO_IMMEDIATE)
X(0x6b, error, NO_FLAG, NO_IMMEDIATE)
X(0x6c, error, NO_FLAG, NO_IMMEDIATE)
X(0x6d, error, NO_FLAG, NO_IMMEDIATE)
X(0x6e, error, NO_FLAG, NO_IMMEDIATE)
X(0x6f, error, NO_FLAG, NO_IMMEDIATE)
X(0x70, error, NO_FLAG, NO_IMMEDIATE)
X(0x71, error, NO_FLAG, NO_IMMEDIATE)
X(0x72, error, NO_FLAG, NO_IMMEDIATE)
X(0x73, error, NO_FLAG, NO_IMMEDIATE)
X(0x74, error, NO_FLAG, NO_IMMEDIATE)
X(0x75, error, NO_FLAG, NO_IMMEDIATE)
X(0x76, error, NO_FLAG, NO_IMMEDIATE)
X(0x77, error, NO_FLAG, NO_IMMEDIATE)
X(0x78, error, NO_FLAG, NO_IMMEDIATE)
X(0x79, error, NO_FLAG, NO_IMMEDIATE)
X(0x7a, error, NO_FLAG, NO_IMMEDIATE)
X(0x7b, error, NO_FLAG, NO_IMMEDIATE)
X(0x7c, error, NO_FLAG, NO_IMMEDIATE)
X(0x7d, error, NO_FLAG, NO_IMMEDIATE)
X(0x7e, error, NO_FLAG, NO_IMMEDIATE)
X(0x7f, error, NO_FLAG, NO_IMMEDIATE)
X(0x80, error, NO_FLAG, NO_IMMEDIATE)
X(0x81, error, NO_FLAG, NO_IMMEDIATE)
X(0x82, error, NO_FLAG, NO_IMMEDIATE)
X(0x83, error, NO_FLAG, NO_IMMEDIATE)
X(0x84, error, NO_FLAG, NO_IMMEDIATE)
X(0x85, error, NO_FLAG, NO_IMMEDIATE)
X(0x86, error, NO_FLAG, NO_IMMEDIATE)
X(0x87, error, NO_FLAG, NO_IMMEDIATE)
X(0x88, error, NO_FLAG, NO_IMMEDIATE)
X(0x89, error, NO_FLAG, NO_IMMEDIATE)
X(0x8a, error, NO_FLAG, NO_IMMEDIATE)
X(0x8b, error, NO_FLAG, NO_IMMEDIATE)
X(0x8c, error, NO_FLAG, NO_IMMEDIATE)
X(0x8d, error, NO_FLAG, NO_IMMEDIATE)
X(0x8e, error, NO_FLAG, NO_IMMEDIATE)
X(0x8f, error, NO_FLAG, NO_IMMEDIATE)
X(0x90, error, NO_FLAG, NO_IMMEDIATE)
X(0x91, error, NO_FLAG, NO_IMMEDIATE)
X(0x92, error, NO_FLAG, NO_IMMEDIATE)
X(0x93, error, NO_FLAG, NO_IMMEDIATE)
X(0x94, error, NO_FLAG, NO_IMMEDIATE)
X(0x95, error, NO_FLAG, NO_IMMEDIATE)
X(0x96, error, NO_FLAG, NO_IMMEDIATE)
X(0x97, error, NO_FLAG, NO_IMMEDIATE)
X(0x98, error, NO_FLAG, NO_IMMEDIATE)
X(0x99, error, NO_FLAG, NO_IMMEDIATE)
X(0x9a, error, NO_FLAG, NO_IMMEDIATE)
X(0x9b, error, NO_FLAG, NO_IMMEDIATE)
X(0x9c, error, NO_FLAG, NO_IMMEDIATE)
X(0x9d, error, NO_FLAG, NO_IMMEDIATE)
X(0x9e, error, NO_FLAG, NO_IMMEDIATE)
X(0x9f, error, NO_FLAG, NO_IMMEDIATE)
X(0xa0, error, NO_FLAG, NO_IMMEDIATE)
X(0xa1, error, NO_FLAG, NO_IMMEDIATE)
X(0xa2, error, NO_FLAG, NO_IMMEDIATE)
X(0xa3, error, NO_FLAG, NO_IMMEDIATE)
X(0xa4, error, NO_FLAG, NO_IMMEDIATE)
X(0xa5, error, NO_FLAG, NO_IMMEDIATE)
X(0xa6, error, NO_FLAG, NO_IMMEDIATE)
X(0xa7, error, NO_FLAG, NO_IMMEDIATE)
X(0xa8, error, NO_FLAG, NO_IMMEDIATE)
X(0xa9, error, NO_FLAG, NO_IMMEDIATE)
X(0xaa, error, NO_FLAG, NO_IMMEDIATE)
X(0xab, error, NO_FLAG, NO_IMMEDIATE)
X(0xac, error, NO_FLAG, NO_IMMEDIATE)
X(0xad, error, NO_FLAG, NO_IMMEDIATE)
X(0xae, error, NO_FLAG, NO_IMMEDIATE)
X(0xaf, error, NO_FLAG, NO_IMMEDIATE)
X(0xb0, error, NO_FLAG, NO_IMMEDIATE)
X(0xb1, error, NO_FLAG, NO_IMMEDIATE)
X(0xb2, error, NO_FLAG, NO_IMMEDIATE)
X(0xb3, error, NO_FLAG, NO_IMMEDIATE)
X(0xb4, error, NO_FLAG, NO_IMMEDIATE)
X(0xb5, error, NO_FLAG, NO_IMMEDIATE)
X(0xb6, error, NO_FLAG, NO_IMMEDIATE)
X(0xb7, error, NO_FLAG, NO_IMMEDIATE)
X(0xb8, error, NO_FLAG, NO_IMMEDIATE)
X(0xb9, error, NO_FLAG, NO_IMMEDIATE)
X(0xba, error, NO_FLAG, NO_IMMEDIATE)
X(0xbb, error, NO_FLAG, NO_IMMEDIATE)
X(0xbc, error, NO_FLAG, NO_IMMEDIATE)
X(0xbd, error, NO_FLAG, NO_IMMEDIATE)
X(0xbe, error, NO_FLAG, NO_IMMEDIATE)
X(0xbf, error, NO_FLAG, NO_IMMEDIATE)
X(0xc0, error, NO_FLAG, NO_IMMEDIATE)
X(0xc1, error, NO_FLAG, NO_IMMEDIATE)
X(0xc2, error, NO_FLAG, NO_IMMEDIATE)
X(0xc3, error, NO_FLAG, NO_IMMEDIATE)
X(0xc4, error, NO_FLAG, NO_IMMEDIATE)
X(0xc5, error, NO_FLAG, NO_IMMEDIATE)
X(0xc6, error, NO_FLAG, NO_IMMEDIATE)
X(0xc7, error, NO_FLAG, NO_IMMEDIATE)
X(0xc8, error, NO_FLAG, NO_IMMEDIATE)
X(0xc9, error, NO_FLAG, NO_IMMEDIATE)
X(0xca, error, NO_FLAG, NO_IMMEDIATE)
X(0xcb, error, NO_FLAG, NO_IMMEDIATE)
X(0xcc, error, NO_FLAG, NO_IMMEDIATE)
X(0xcd, error, NO_FLAG, NO_IMMEDIATE)
X(0xce, error, NO_FLAG, NO_IMMEDIATE)
X(0xcf, error, NO_FLAG, NO_IMMEDIATE)
X(0xd0, error, NO_FLAG, NO_IMMEDIATE)
X(0xd1, error, NO_FLAG, NO_IMMEDIATE)
X(0xd2, error, NO_FLAG, NO_IMMEDIATE)
X(0xd3, error, NO_FLAG, NO_IMMEDIATE)
X(0xd4, error, NO_FLAG, NO_IMMEDIATE)
X(0xd5, error, NO_FLAG, NO_IMMEDIATE)
X(0xd6, error, NO_FLAG, NO_IMMEDIATE)
X(0xd7, error, NO_FLAG, NO_IMMEDIATE)
X(0xd8, error, NO_FLAG, NO_IMMEDIATE)
X(0xd9, error, NO_FLAG, NO_IMMEDIATE)
X(0xda, error, NO_FLAG, NO_IMMEDIATE)
X(0xdb, error, NO_FLAG, NO_IMMEDIATE)
X(0xdc, error, NO_FLAG, NO_IMMEDIATE)
X(0xdd, error, NO_FLAG, NO_IMMEDIATE)
X(0xde, error, NO_FLAG, NO_IMMEDIATE)
X(0xdf, error, NO_FLAG, NO_IMMEDIATE)
X(0xe0, error, NO_FLAG, NO_IMMEDIATE)
X(0xe1, error, NO_FLAG, NO_IMMEDIATE)
X(0xe2, error, NO_FLAG, NO_IMMEDIATE)
X(0xe3, error, NO_FLAG, NO_IMMEDIATE)
X(0xe4, error, NO_FLAG, NO_IMMEDIATE)
X(0xe5, error, NO_FLAG, NO_IMMEDIATE)
X(0xe6, error, NO_FLAG, NO_IMMEDIATE)
X(0xe7, error, NO_FLAG, NO_IMMEDIATE)
X(0xe8, error, NO_FLAG, NO_IMMEDIATE)
X(0xe9, error, NO_FLAG, NO_IMMEDIATE)
X(0xea, error, NO_FLAG, NO_IMMEDIATE)
X(0xeb, error, NO_FLAG, NO_IMMEDIATE)
X(0xec, error, NO_FLAG, NO_IMMEDIATE)
X(0xed, error, NO_FLAG, NO_IMMEDIATE)
X(0xee, error, NO_FLAG, NO_IMMEDIATE)
X(0xef, error, NO_FLAG, NO_IMMEDIATE)
X(0xf0, error, NO_FLAG, NO_IMMEDIATE)
X(0xf1, error, NO_FLAG, NO_IMMEDIATE)
X(0xf2, error, NO_FLAG, NO_IMMEDIATE)
X(0xf3, error, NO_FLAG, NO_IMMEDIATE)
X(0xf4, error, NO_FLAG, NO_IMMEDIATE)
X(0xf5, error, NO_FLAG, NO_IMMEDIATE)
X(0xf6, error, NO_FLAG, NO_IMMEDIATE)
X(0xf7, error, NO_FLAG, NO_IMMEDIATE)
X(0xf8, error, NO_FLAG, NO_IMMEDIATE)
X(0xf9, error, NO_FLAG, NO_IMMEDIATE)
X(0xfa, error, NO_FLAG, NO_IMMEDIATE)
X(0xfb, error, NO_FLAG, NO_IMMEDIATE)
X(0xfc, error, NO_FLAG, NO_IMMEDIATE)
X(0xfd, error, NO_FLAG, NO_IMMEDIATE)
X(0xfe, error, NO_FLAG, NO_IMMEDIATE)
X(0xff, error, NO_FLAG, NO_IMMEDIATE)