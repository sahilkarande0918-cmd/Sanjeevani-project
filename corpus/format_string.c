/* Sanjeevani corpus 3/3 - format string bug.
 *
 * BUG: printf(in) treats whatever the user typed as a *format string*.
 *      Typing "%s%s%s%s" makes printf read pointers that were never passed,
 *      and "%n" makes it WRITE to one. Either way it reads or writes memory
 *      the caller never intended.
 *
 * The fix is one of the smallest in security: printf("%s", in).
 */
#include <stdio.h>
#include <string.h>

#define MAXIN 64

int main(void)
{
    char in[MAXIN];

    if (!fgets(in, sizeof in, stdin))
        return 1;
    in[strcspn(in, "\n")] = '\0';

    printf(in);                 /* BUG: user input used as format string */
    putchar('\n');
    return 0;
}
