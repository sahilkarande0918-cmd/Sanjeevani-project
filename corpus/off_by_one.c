/* Sanjeevani corpus 2/3 - off-by-one write.
 *
 * BUG: slot[] has NSLOT entries, but the loop condition is  i <= slots,
 *      so it runs one iteration too many and writes slot[NSLOT] - which is
 *      one past the end of the array.
 *
 * Why an array of POINTERS rather than an array of chars:
 * we first tried overflowing a char buffer by one byte. It never crashed.
 * A single stray byte only nudges the neighbouring value slightly - a
 * pointer stays inside the same mapped page, a length stays plausible - so
 * nothing faults and the fuzzer finds nothing. Overrunning an array of
 * pointers overwrites a whole 8-byte pointer with input bytes, which gives a
 * wild address for any input at all. That makes the crash depend only on the
 * input's LENGTH, never on the particular bytes, so it reproduces every time.
 *
 * Crashes on any input of 24 or more characters. Exits cleanly below that.
 */
#include <stdio.h>
#include <string.h>

#define NSLOT 3

struct rec {
    char *slot[NSLOT];
    char *tail;                 /* C guarantees this sits right after slot[] */
};

int main(void)
{
    char in[64];

    memset(in, 0, sizeof in);   /* no uninitialised stack, so runs are repeatable */
    if (!fgets(in, sizeof in, stdin))
        return 1;

    size_t n     = strcspn(in, "\n");
    size_t slots = n / 8;
    if (slots > NSLOT)
        slots = NSLOT;

    struct rec r;
    r.tail = "end";

    for (size_t i = 0; i <= slots; i++)         /* BUG: should be i < slots */
        memcpy(&r.slot[i], in + i * 8, 8);

    puts(r.tail);               /* tail was overwritten with input bytes */
    return 0;
}
