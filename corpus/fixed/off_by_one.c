/* GROUND TRUTH fix for corpus/off_by_one.c
 *
 * One character changed: <= became <. That is the entire fix.
 * The loop now writes indices 0..len-1, all inside the buffer.
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

    for (size_t i = 0; i < len; i++)    /* FIX: was i <= len */
        tbl[i] = in[i];

    printf("%zu\n", len);
    free(tbl);
    return 0;
}
