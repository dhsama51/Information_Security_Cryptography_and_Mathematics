#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TRUE 1
#define FALSE 0

#define Q_SIZE 20000000

typedef int element;
typedef struct _queueType_ {
	element queue[Q_SIZE];
	int front, rear;
}QueueType;

QueueType* createQueue()
{
	QueueType* Q;
	Q = (QueueType*)calloc(1, sizeof(QueueType));
	Q->front = -1;
	Q->rear = -1;

	return Q;
}

int isFull(QueueType* Q)
{
	if (Q->rear == Q_SIZE - 1) return TRUE;
	else return FALSE;
}

int isEmpty(QueueType* Q)
{
	if (Q->front == Q->rear) return TRUE;
	else return FALSE;
}

void enQueue(QueueType* Q, element item)
{
	if (isFull(Q)) return;
	else {
		Q->rear += 1;
		Q->queue[Q->rear] = item;
	}
}
element deQueue(QueueType* Q)
{
	if (isEmpty(Q)) return -1;
	else {
		Q->front += 1;
		return Q->queue[Q->front];
	}
}

element peek(QueueType* Q)
{
	if (isEmpty(Q)) return -1;
	else return Q->queue[Q->front + 1];
}

void test_18258()
{
	QueueType* Q = createQueue();
	char str[10] = { 0, }, buf = 0;
	int numOfOrder = 0, i = 0;
	element n;
	scanf("%d%c", &numOfOrder, &buf);

	for (i = 0; i < numOfOrder; i++)
	{
		memset(str, 0, 10);
		scanf("%s", str);
		if (!strcmp(str, "push"))
		{
			scanf("%d%c\n", &n, &buf);
			enQueue(Q, n);
		}
		else if (!strcmp(str, "pop"))
		{
			printf("%d\n", deQueue(Q));
		}
		else if (!strcmp(str, "size"))
		{
			printf("%d\n", Q->rear - Q->front);
		}
		else if (!strcmp(str, "empty"))
		{
			printf("%d\n", isEmpty(Q));
		}
		else if (!strcmp(str, "front"))
		{
			if (!isEmpty(Q))
				printf("%d\n", Q->queue[Q->front + 1]);
			else printf("-1\n");
		}
		else if (!strcmp(str, "back"))
		{
			if (!isEmpty(Q))
				printf("%d\n", Q->queue[Q->rear]);
			else printf("-1\n");
		}
	}
}

void test_2164()
{
	QueueType* Q = createQueue();
	int n = 0, i = 0, j = 0, x = 2, oddOrEven = 0;
	scanf("%d", &n);
	
	for (i = 1; i < n + 1; i++)
	{
		enQueue(Q, i);
	}
	while (Q->rear - Q->front != 1)
	{
		switch (oddOrEven % 2)
		{
		case 0:
		{
			deQueue(Q);
			oddOrEven += 1;
		}
		case 1:
		{
			enQueue(Q, deQueue(Q));
			oddOrEven += 1;
		}
		}
	}
	printf("%d", deQueue(Q));
}

int main()
{
	test_18258();
	//test_2164();

	return 0;
}