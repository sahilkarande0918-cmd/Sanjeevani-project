/* DELIBERATELY WRONG patch - the prover MUST reject this.
 *
 * The memory bug is genuinely fixed: the copy is bounded, nothing overflows.
 * A fuzzer would run this for a week and report it clean, because it never
 * crashes.
 *
 * But it also changed the greeting from "hi" to "hello". That is a silent
 * behaviour change on every single input - exactly the kind of regression an
 * LLM-generated patch introduces while "tidying up", and exactly what the
 * EQUIVALENCE half exists to catch.
 */
#include <stdio.h>
#include <string.h>

#define MAXIN 32

void greet(const char *name)
{
    char buf[8];
    strncpy(buf, name, sizeof buf - 1);
    buf[sizeof buf - 1] = '\0';
    printf("hello %s\n", buf);      /* WRONG: was "hi %s\n" */
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
