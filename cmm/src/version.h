/* Static version string for `cmm -v`. Bump by hand on release.

   (Formerly auto-generated from `git describe`, but the Makefile generator's
   `[ -d .git ]` guard never fired — cmm/ has no .git of its own — so it only
   ever shipped a frozen 2017 string. Kept static and honest instead.) */
#ifndef VERSION_H
#define VERSION_H

#define CMM_VERSION "cmm-6.12"

#endif /* VERSION_H */
