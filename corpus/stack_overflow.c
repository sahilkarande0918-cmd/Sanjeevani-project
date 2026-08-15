/* Sanjeevani corpus 1/3 - classic stack buffer overflow.
 *
 * BUG: strcpy() copies until it hits a NUL byte. It has no idea how big the
 *      destination is. Any input longer than 7 characters runs off the end of
 *      buf[8] and smashes the stack.
 *
 * Kept deliberately tiny: every extra byte of input multiplies the number of
 * paths angr has to explore in Phase 2. 32 bytes in, 8 bytes of buffer.
 */
#include <stdio.h>
#include <string.h>

#define MAXIN 32

void greet(const char *name)
{
    char buf[8];
    strcpy(buf, name);          /* BUG: unbounded copy */
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
