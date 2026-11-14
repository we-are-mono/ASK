# Since Linux 6.16, libperf generates arm64's unistd_64.h through
# scripts/Makefile.asm-headers (tools/lib/perf/Makefile, uapi-asm-generic),
# which reads the generic header list and the arch's syscall ABI selection from
# the kernel tree. walnascar's PERF_SRC predates that and copies neither.
PERF_SRC:append = " include/uapi/asm-generic/Kbuild arch/arm64/kernel/Makefile.syscalls"
