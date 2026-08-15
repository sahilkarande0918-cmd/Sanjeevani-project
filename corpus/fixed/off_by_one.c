/* GROUND TRUTH fix for corpus/off_by_one.c
 *
 * One character changed: <= became <. The loop now writes slot[0..slots-1],
 * every one of them inside the array, and r.tail is left alone.
 */
#include <stdio.h>
#include <string.h>

#define NSLOT 3

struct rec {
    char *slot[NSLOT];
    char *tail;
};

int main(void)
{
    char in[64];

    memset(in, 0, sizeof in);
    if (!fgets(in, sizeof in, stdin))
        return 1;

    size_t n     = strcspn(in, "\n");
    size_t slots = n / 8;
    if (slots > NSLOT)
        slots = NSLOT;

    struct rec r;
    r.tail = "end";

    for (size_t i = 0; i < slots; i++)          /* FIX: was i <= slots */
        memcpy(&r.slot[i], in + i * 8, 8);

    puts(r.tail);
    return 0;
}
