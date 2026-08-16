/* DELIBERATELY WRONG patch - the prover MUST reject this.
 *
 * This is the "looks like a fix, isn't one" case. Someone clamped `slots` and
 * added a bounds comment, so it reads like careful defensive code. The loop
 * condition is still <=, so it still writes one past the end and still
 * corrupts r.tail.
 *
 * Behaviour is identical to the original, so the EQUIVALENCE half is perfectly
 * happy. Only the SAFETY half can catch this, which is why the verdict needs
 * both and why "outputs match" alone would be a dangerous thing to certify.
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
    if (slots > NSLOT)          /* bounds check that looks reassuring */
        slots = NSLOT;          /* ...and changes nothing about the bug */

    struct rec r;
    r.tail = "end";

    for (size_t i = 0; i <= slots; i++)     /* STILL WRONG: <= not < */
        memcpy(&r.slot[i], in + i * 8, 8);

    puts(r.tail);
    return 0;
}
