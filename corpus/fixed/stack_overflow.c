/* GROUND TRUTH fix for corpus/stack_overflow.c
 *
 * Only the copy changed. Everything else is byte-identical to the broken
 * version on purpose: Phase 2 proves the two binaries differ in exactly one
 * place, so any unrelated edit here would be a false positive.
 *
 * strncpy() takes a maximum length. sizeof buf - 1 leaves room for the
 * terminating NUL, which strncpy does NOT add when it truncates - hence the
 * explicit assignment on the next line.
 */
#include <stdio.h>
#include <string.h>

#define MAXIN 32

void greet(const char *name)
{
    char buf[8];
    strncpy(buf, name, sizeof buf - 1);   /* FIX */
    buf[sizeof buf - 1] = '\0';           /* FIX: strncpy may not terminate */
    printf("hi %s\n", buf);
}

int main(void)
{
    char in[MAXIN];

    if (!fgets(in, sizeof in, stdin))
        return 1;
    in[strcspn(in, "\n")] = '\0';

    greet(in);
    return 0;
}
