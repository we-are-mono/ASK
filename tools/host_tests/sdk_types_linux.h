/* Host substitutions for the SDK's kernel types and MMIO access boundary. */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
typedef float float_t;
typedef double double_t;
typedef uint64_t physAddress_t;
#define _Packed
#define _PackedType __attribute__((packed))
#define __iomem
#define __packed __attribute__((packed))
#define TRUE true
#define FALSE false
#define raw_smp_processor_id() 0
#define GET_UINT8(x) (x)
#define GET_UINT16(x) (x)
#define GET_UINT32(x) (x)
#define GET_UINT64(x) (x)
#define WRITE_UINT8(x, y) ((x) = (y))
#define WRITE_UINT16(x, y) ((x) = (y))
#define WRITE_UINT32(x, y) ((x) = (y))
#define WRITE_UINT64(x, y) ((x) = (y))
