/* Sanjeevani corpus 2/3 - off-by-one write.
 *
 * BUG: the loop says  i <= len  where it should say  i < len.
 *      That writes one byte past the end of the buffer. When the input is
 *      exactly N bytes long, that byte lands outside the malloc'd chunk and
 *      corrupts glibc's heap metadata, so free() aborts.
 *
 * N is 24 on purpose: malloc(24) hands back exactly 24 usable bytes, so
 * index 24 is genuinely out of bounds. With a smaller N, malloc's rounding
 * would silently absorb the overflow and nothing would crash.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 24

int main(void)
{
    char in[64];

    if (!fgets(in, sizeof in, stdin))
        return 1;

    size_t len = strcspn(in, "\n");
    if (len > N)
        len = N;

    char *tbl = malloc(N);
    if (!tbl)
        return 1;

    for (size_t i = 0; i <= len; i++)   /* BUG: should be i < len */
        tbl[i] = in[i];

    printf("%zu\n", len);
    free(tbl);                          /* aborts when the heap was corrupted */
    return 0;
}
