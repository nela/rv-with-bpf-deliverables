#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define COMMAND_BUF_LEN 16
#define STACK_BUFF_LEN  10

int buffer[STACK_BUFF_LEN];

void push(int number, int *i) {
  buffer[*i] = number;
  // *i += 1;
}

int pop(int *i) {
  *i -= 1;
  int result = buffer[*i];
  return result;
}

int empty(int *i) { return *i == 0; }

int full(int *i) { return *i == 100; }

int main(void) {
  int index, number, retval;
  char command[COMMAND_BUF_LEN];

  retval = scanf("%s", command);
  index = 0;

  while (retval != EOF) {
    if (strncmp(command, "push", COMMAND_BUF_LEN) == 0) {
      scanf("%d", &number);
      push(number, &index);
      printf("PUSHED %d\n", number);
    }

    if (strncmp(command, "pop", COMMAND_BUF_LEN) == 0) {
        if (index == 0) printf("NO POP\n");
        else printf("POPPED %d\n", pop(&index));
    }

    if (strncmp(command, "empty", COMMAND_BUF_LEN) == 0)
      printf("%s\n", empty(&index) ? "YES" : "NO");

    if (strncmp(command, "full", COMMAND_BUF_LEN) == 0)
      printf("%s\n", full(&index) ? "YES" : "NO");

    retval = scanf("%s", command);
  }

  return 0;
}
