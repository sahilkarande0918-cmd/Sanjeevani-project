/* GROUND TRUTH fix for corpus/format_string.c
 *
 * The user's text is now an ARGUMENT, not the format. printf will print it
 * literally, so "%n" is just two harmless characters on screen.
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

    printf("%s", in);           /* FIX: input is data, not format */
    putchar('\n');
    return 0;
}
