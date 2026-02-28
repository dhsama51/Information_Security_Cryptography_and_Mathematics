#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STACK_SIZE 1000000
typedef int element;

element stack[STACK_SIZE];
int top = -1;

void init()
{
	top = -1;
}

int isEmpty()
{
	if (top == -1) return 1;
	else return 0;
}

int isFull()
{
	if (top == STACK_SIZE - 1) return 1;
	else return 0;
}

void push(element item)
{
	if (isFull()) return -1;
	else stack[++top] = item;
}

element pop() {
	if (isEmpty()) return -1;
	else return stack[top--];
}

element peek()
{
	if (isEmpty()) return -1;
	else return stack[top];
}

void test_10828()
{
	char str[10] = { 0, }, buf = 0;
	int numOfOrder = 0, i = 0;
	element n;
	scanf("%d%c", &numOfOrder, &buf);

	for (i = 0; i < numOfOrder; i++)
	{
		memset(str, 0, 5);
		scanf("%s", str);
		if (!strcmp(str, "push"))
		{
			scanf("%d%c\n", &n, &buf);
			push(n);
		}
		else if (!strcmp(str, "pop"))
		{
			printf("%d\n", pop());
		}
		else if (!strcmp(str, "size"))
		{
			printf("%d\n", top + 1);
		}
		else if (!strcmp(str, "empty"))
		{
			printf("%d\n", isEmpty());
		}
		else if (!strcmp(str, "top"))
		{
			printf("%d\n", peek());
		}
	}
}

char plusminus[200000] = { 0, };
element n_1874[100000] = { 0, };
void test_1874()
{
	int numOfNumber = 0, i = 0, check = 0, plusminusIndex = 0;
	element num = 1, buf = 0;
	scanf("%d", &numOfNumber);

	for (i = 0; i < numOfNumber; i++)
	{
		scanf("%d", &n_1874[i]);
	}

	i = 0;
	while (1)
	{
		if (peek() < n_1874[i])
		{
			push(num++);
			plusminus[plusminusIndex++] = '+';
		}
		else if (peek() == n_1874[i])
		{
			buf = pop();
			plusminus[plusminusIndex++] = '-';
			i += 1;
		}
		else
		{
			printf("NO\n");
			check = 1;
			break;
		}
		if (plusminusIndex == numOfNumber * 2) break;
	}

	if (check == 0)
	{
		for (i = 0; i < plusminusIndex; i++)
		{
			printf("%c\n", plusminus[i]);
		}
	}
}

element n_17298[1000000] = { 0, }, NGE[1000000] = { 0, };
void test_17298()
{
	int numOfNumber = 0, i = 0;

	scanf("%d", &numOfNumber);
	for (i = 0; i < numOfNumber; i++)
		scanf("%d", &n_17298[i]);
	push(0);
	for (i = 1; i < numOfNumber; i++)
	{
		if (isEmpty()) push(i);
		while (!isEmpty() && n_17298[peek()] < n_17298[i])
		{
			NGE[peek()] = n_17298[i];
			pop();
		}
		push(i);
	}
	while (!isEmpty())
	{
		NGE[peek()] = -1;
		pop();
	}
	for (i = 0; i < numOfNumber; i++)
		printf("%d ", NGE[i]);
}

int main()
{
	test_10828();
	//test_1874();
	//test_17298();

	return 0;
}