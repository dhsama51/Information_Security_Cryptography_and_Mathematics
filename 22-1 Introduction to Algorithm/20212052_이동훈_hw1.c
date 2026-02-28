#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void checkfrequency(char* arr, int* frequency)
{
	int i = 0;
	int flag = 0;

	for (i = 0; i < 1024; i++)
	{
		if (flag == 1)
			break;
		switch (arr[i])
		{
		case 'A':
		case 'a':
			frequency[0] += 1;
			break;
		case 'B':
		case 'b':
			frequency[1] += 1;
			break;
		case 'C':
		case 'c':
			frequency[2] += 1;
			break;
		case 'D':
		case 'd':
			frequency[3] += 1;
			break;
		case 'E':
		case 'e':
			frequency[4] += 1;
			break;
		case 'F':
		case 'f':
			frequency[5] += 1;
			break;
		case 'G':
		case 'g':
			frequency[6] += 1;
			break;
		case 'H':
		case 'h':
			frequency[7] += 1;
			break;
		case 'I':
		case 'i':
			frequency[8] += 1;
			break;
		case 'J':
		case 'j':
			frequency[9] += 1;
			break;
		case 'K':
		case 'k':
			frequency[10] += 1;
			break;
		case 'L':
		case 'l':
			frequency[11] += 1;
			break;
		case 'M':
		case 'm':
			frequency[12] += 1;
			break;
		case 'N':
		case 'n':
			frequency[13] += 1;
			break;
		case 'O':
		case 'o':
			frequency[14] += 1;
			break;
		case 'P':
		case 'p':
			frequency[15] += 1;
			break;
		case 'Q':
		case 'q':
			frequency[16] += 1;
			break;
		case 'R':
		case 'r':
			frequency[17] += 1;
			break;
		case 'S':
		case 's':
			frequency[18] += 1;
			break;
		case 'T':
		case 't':
			frequency[19] += 1;
			break;
		case 'U':
		case 'u':
			frequency[20] += 1;
			break;
		case 'V':
		case 'v':
			frequency[21] += 1;
			break;
		case 'W':
		case 'w':
			frequency[22] += 1;
			break;
		case 'X':
		case 'x':
			frequency[23] += 1;
			break;
		case 'Y':
		case 'y':
			frequency[24] += 1;
			break;
		case 'Z':
		case 'z':
			frequency[25] += 1;
			break;
		case '\0':
			flag = 1;
			break;
		default:
			break;
		}
	}
}

void test1()
{
	int i = 0;
	int frequency[26] = {0x00, };
	char arr[1025] = {0x00, };

	printf("Input a string:\n");
	fgets(arr, 1024, stdin);
	
	checkfrequency(arr, &frequency);
	
	printf("[Alphabet frequency]\n");
	for (i = 0; i < 26; i++)
	{
		printf("%c: %d\n", 'a' + i, frequency[i]);
	}
	printf("\n\nBye!");
}

#define MAXSTRLEN	32

typedef struct _LIST_NODE_
{
	char data[MAXSTRLEN];
	struct _LIST_NODE_* link;
}LIST_NODE;

typedef	struct _LINKED_LIST_H_
{
	LIST_NODE* head;
}LINKEDLIST_H;

LINKEDLIST_H* createLINKEDLIST_H()
{
	LINKEDLIST_H* L = NULL;
	L = (LINKEDLIST_H*)calloc(1, sizeof(LINKEDLIST_H));
	assert(L != NULL);
	L->head = NULL;

	return L;
}

void freeLinkedList_H(LINKEDLIST_H* L)
{
	LIST_NODE* p;

	if (L != NULL)
	{
		while (L->head != NULL)
		{
			p = L->head;
			L->head = L->head->link;
			free(p);
			p = NULL;
		}
		L->head = NULL;
	}
	else
	{
		fprintf(stderr, "Error: NULL list\n");
		return;
	}
}

void printList(LINKEDLIST_H* L)
{
	LIST_NODE* p = NULL;
	p = L->head;

	printf("L = (");
	while (p != NULL)
	{
		printf("%s", p->data);
		p = p->link;
		if (p != NULL)
		{
			printf(", ");
		}
	}
	printf(")\n");
}

void insertFirstNode(LINKEDLIST_H* L, char* x)
{
	LIST_NODE* newNode = NULL;
	newNode = (LIST_NODE*)calloc(1, sizeof(LIST_NODE));
	assert(newNode != NULL);
	newNode->link = NULL;

	strncpy(newNode->data, x, MAXSTRLEN);
	newNode->link = L->head;
	L->head = newNode;
}

void insertLastNode(LINKEDLIST_H* L, char* x)
{
	LIST_NODE* newNode = NULL;
	LIST_NODE* temp = NULL;

	newNode = (LIST_NODE*)calloc(1, sizeof(LIST_NODE));
	assert(newNode != NULL);

	strncpy(newNode->data, x, MAXSTRLEN);
	newNode->link = NULL;

	if (L->head == NULL)
	{
		L->head = newNode;
		return;
	}
	else
	{
		temp = L->head;

		while (temp->link != NULL)
		{
			temp = temp->link;
		}
		temp->link = newNode;
	}
}

LIST_NODE* searchNode(LINKEDLIST_H* L, char* x)
{
	LIST_NODE* temp = NULL;
	temp = L->head;

	while (temp != NULL)
	{
		if (strncmp(temp->data, x, MAXSTRLEN) == 0)
		{
			return temp;
		}
		else
		{
			temp = temp->link;

		}
	}
	return temp;
}

void insertMiddleNode(LINKEDLIST_H* L, LIST_NODE* pre, char* x)
{
	LIST_NODE* newNode = NULL;
	LIST_NODE* temp = NULL;

	newNode = (LIST_NODE*)calloc(1, sizeof(LIST_NODE));
	assert(newNode != NULL);

	strncpy(newNode->data, x, MAXSTRLEN);
	newNode->link = NULL;

	if (L->head == NULL)
	{
		L->head = newNode;
	}
	else if (pre == NULL)
	{
		newNode->link = L->head;
		L->head = newNode;
	}
	else
	{
		newNode->link = pre->link;
		pre->link = newNode;
	}
}

void deleteNode(LINKEDLIST_H* L, LIST_NODE* p)
{
	LIST_NODE* pre = NULL;
	LIST_NODE* cur = NULL;
	LIST_NODE* find = NULL;

	if (L->head == NULL || p == NULL)
	{
		return;
	}

	pre = cur = L->head;

	if (pre == p)
	{
		L->head = pre->link;
		free(pre);
		return;
	}
	cur = cur->link;
	while (cur != NULL)
	{
		if (cur == p)
		{
			find = cur;
			break;
		}
		pre = cur;
		cur = cur->link;
	}

	if (find != NULL)
	{
		pre->link = find->link;
		free(find);
	}
}

void orderedInsert(LINKEDLIST_H* L, char* x)
{
	LIST_NODE* pre = NULL;
	LIST_NODE* cur = NULL;
	LIST_NODE* newNode = NULL;

	newNode = (LIST_NODE*)calloc(1, sizeof(LIST_NODE));
	assert(newNode != NULL);
	strncpy(newNode->data, x, MAXSTRLEN);
	newNode->link = NULL;

	pre = cur = L->head;

	if (cur == NULL)
	{
		L->head = newNode;
		return;
	}
	else
	{
		if (strncmp(cur->data, x, MAXSTRLEN) > 0)
		{
			newNode->link = cur;
			L->head = newNode;
			return;
		}
	}

	cur = cur->link;
	while (cur != NULL)
	{
		if (strncmp(cur->data, x, MAXSTRLEN) > 0)
		{
			break;
		}
		pre = cur;
		cur = cur->link;
	}

	newNode->link = cur;
	pre->link = newNode;
}

void inverseOrderedInsert(LINKEDLIST_H* L, char* x)
{
	LIST_NODE* pre = NULL;
	LIST_NODE* cur = NULL;
	LIST_NODE* newNode = NULL;

	newNode = (LIST_NODE*)calloc(1, sizeof(LIST_NODE));
	assert(newNode != NULL);
	strncpy(newNode->data, x, MAXSTRLEN);
	newNode->link = NULL;

	pre = cur = L->head;

	if (cur == NULL)
	{
		L->head = newNode;
		return;
	}
	else
	{
		if (strncmp(cur->data, x, MAXSTRLEN) < 0)
		{
			newNode->link = cur;
			L->head = newNode;
			return;
		}
	}

	cur = cur->link;
	while (cur != NULL)
	{
		if (strncmp(cur->data, x, MAXSTRLEN) < 0)
		{
			break;
		}
		pre = cur;
		cur = cur->link;
	}

	newNode->link = cur;
	pre->link = newNode;
}

void test2()
{
	LIST_NODE* temp = NULL;

	printf("(1) 리스트에 머리에 노드 삽입하기!\n");
	LINKEDLIST_H* list1 = NULL;
	list1 = createLINKEDLIST_H();

	insertFirstNode(list1, "apple");
	insertFirstNode(list1, "banana");
	insertFirstNode(list1, "cat");
	printList(list1);
	printf("\n\n");
	freeLinkedList_H(list1);

	printf("(2) 리스트에 꼬리에 노드 삽입하기!\n");
	LINKEDLIST_H* list2 = NULL;
	list2 = createLINKEDLIST_H();

	insertLastNode(list2, "apple");
	insertLastNode(list2, "banana");
	insertLastNode(list2, "cat");
	printList(list2);
	printf("\n\n");
	freeLinkedList_H(list2);

	printf("(3) 리스트에서 노드 탐색하기!\n");
	LINKEDLIST_H* list3 = NULL;
	list3 = createLINKEDLIST_H();

	insertFirstNode(list3, "apple");
	insertFirstNode(list3, "banana");
	insertFirstNode(list3, "test");
	insertFirstNode(list3, "cat");
	temp = searchNode(list3, "banana");
	printf("[%s]를 찾았습니다.\n", temp->data);
	temp = searchNode(list3, "test");
	printf("[%s]를 찾았습니다.\n", temp->data);
	printf("\n\n");
	freeLinkedList_H(list3);
	temp = NULL;

	printf("(4) 리스트에서 중간에 노드 삽입하기!\n");
	LINKEDLIST_H* list4 = NULL;
	list4 = createLINKEDLIST_H();

	insertFirstNode(list4, "apple");
	insertFirstNode(list4, "test");
	insertFirstNode(list4, "banana");
	insertFirstNode(list4, "cat");
	temp = searchNode(list4, "test");
	insertMiddleNode(list4, temp, "zero");
	printList(list4);
	printf("\n\n");
	freeLinkedList_H(list4);
	temp = NULL;

	printf("(5) 리스트에 정렬하여 노드 삽입하기!\n");
	LINKEDLIST_H* list5 = NULL;
	list5 = createLINKEDLIST_H();
	
	orderedInsert(list5, "friday");
	orderedInsert(list5, "blue");
	orderedInsert(list5, "test");
	orderedInsert(list5, "absolute");
	orderedInsert(list5, "attain");
	orderedInsert(list5, "affine");
	printList(list5);
	printf("\n\n");
	freeLinkedList_H(list5);
	temp = NULL;

	printf("(6) 리스트에서 노드 삭제하기!\n");
	LINKEDLIST_H* list6 = NULL;
	list6 = createLINKEDLIST_H();

	orderedInsert(list6, "friday");
	orderedInsert(list6, "blue");
	orderedInsert(list6, "test");
	orderedInsert(list6, "absolute");
	orderedInsert(list6, "attain");
	orderedInsert(list6, "affine");
	temp = searchNode(list6, "affine");
	deleteNode(list6, temp);
	printList(list6);
	printf("\n\n");
	freeLinkedList_H(list6);
	temp = NULL;

	printf("(7) 리스트에 거꾸로 정렬하여 노드 삽입하기!\n");
	LINKEDLIST_H* list7 = NULL;
	list7 = createLINKEDLIST_H();

	inverseOrderedInsert(list7, "friday");
	inverseOrderedInsert(list7, "blue");
	inverseOrderedInsert(list7, "test");
	inverseOrderedInsert(list7, "absolute");
	inverseOrderedInsert(list7, "attain");
	inverseOrderedInsert(list7, "affine");
	printList(list7);
	printf("\n\n");
	freeLinkedList_H(list7);
	temp = NULL;
}

#define TRUE 1
#define FALSE 0

typedef int element;

typedef struct stackNode {
	element data;
	struct stackNode* link;
}stackNode;

void init(stackNode** top)
{
	*top = NULL;
}

int isEmpty(stackNode** top)
{
	if (*top == NULL) {
		return 1;
	}
	else {
		return 0;
	}
}

void push(element item, stackNode** top)
{
	stackNode* temp = (stackNode*)calloc(1, sizeof(stackNode));
	temp->data = item;
	temp->link = *top;
	*top = temp;
}

element pop(stackNode** top)
{
	element item;
	stackNode* temp = *top;

	if (*top == NULL)
	{
		printf("\n\n Stack is empty\n");
		return -1;
	}
	else {
		item = temp->data;
		*top = temp->link;
		free(temp);

		return item;
	}
}

element peek(stackNode** top)
{
	if (*top == NULL)
	{
		printf("\n\n Stack is empty\n");
		return -1;
	}
	else {
		return ((*top)->data);
	}
}

void printStack(stackNode** top)
{
	stackNode* p = *top;
	printf("\n STACK [ ");
	while (p) {
		printf("%c ", p->data);
		p = p->link;
	}
	printf("]");
}

void freeStack(stackNode** top)
{
	stackNode* pre = NULL;
	stackNode* cur = NULL;

	pre = cur = *top;
	while (cur != NULL)
	{
		pre = cur;
		cur = cur->link;
		free(pre);
		pre = NULL;
	}
}

int testPair(char* exp, stackNode** top)
{
	char symbol, open_pair;
	int i, len;

	init(&top);
	len = strlen(exp);


	for (i = 0; i < len; i++)
	{
		symbol = exp[i];
		switch (symbol)
		{
		case '(':
		case '{':
		case '[':
			push(symbol, &top);
			break;

		case ')':
		case '}':
		case ']':
			if (isEmpty(&top))
			{
				return FALSE;
			}
			else
			{
				open_pair = pop(&top);

				if ((open_pair == '(' && symbol != ')') ||
					(open_pair == '{' && symbol != '}') ||
					(open_pair == '[' && symbol != ']')) {
					return FALSE;
				}
			}
			break;
		}
	}
	if (isEmpty(&top)) {
		return TRUE;
	}
	else {
		return FALSE;
	}
}
int precedence(char op, stackNode** top)
{
	switch (op)
	{
	case '(':
	case ')':
		return 0;
	case '+':
	case '-':
		return 1;
	case '*':
	case '/':
	case '%':
		return 2;
	}
	return -1;
}

void infix_to_postfix(char* infix, char* postfix, stackNode* top)
{
	isEmpty(&top);
	int i = 0;
	int j = 0;
	char c, op;

	while (infix[i] != '\0')
	{
		c = infix[i++];

		if (c >= '0' && c <= '9')
		{
			postfix[j++] = c;

			while (infix[i] >= '0' && infix[i] <= '9')
			{
				postfix[j++] = infix[i++];
			}
			postfix[j++] = ' ';
		}
		else if (c == '(')
		{
			push(c, &top);
		}
		else if (c == ')')
		{
			while (!isEmpty(&top))
			{
				op = pop(&top);
				if (op == '(')
				{
					break;
				}
				else {
					postfix[j++] = op;
					postfix[j++] = ' ';
				}
			}
		}
		else if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%')
		{
			while (!isEmpty(&top)) {
				op = peek(&top);
				if (precedence(c, &top) <= precedence(op, &top))
				{
					op = pop(&top);
					postfix[j++] = op;
					postfix[j++] = ' ';
				}
				else {
					break;
				}
			}
			push(c, &top);
		}
	}
	while (!isEmpty(&top))
	{
		postfix[j++] = pop(&top);
		postfix[j++] = ' ';
	}
	postfix[j] = '\0';
}

element evalPostfix(char* exp, stackNode* top)
{
	int opr1, opr2, value, i;
	int length = strlen(exp);
	char symbol;

	init(&top);

	for (i = 0; i < length; i++)
	{
		symbol = exp[i];
		if (symbol >= '0' && symbol <= '9')
		{
			value = symbol - '0';
			i += 1;
			while (exp[i] >= '0' && symbol <= '9') {
				value *= 10;
				value += (exp[i] - '0');
				i += 1;
			}
			push(value, &top);
		}
		else if (symbol == '+' || symbol == '-' || symbol == '*' || symbol == '/' || symbol == '%')
		{
			opr2 = pop(&top);
			opr1 = pop(&top);

			switch (symbol)
			{
			case '+':	push(opr1 + opr2, &top); break;
			case '-':	push(opr1 - opr2, &top); break;
			case '*':	push(opr1 * opr2, &top); break;
			case '/':	push(opr1 / opr2, &top); break;
			case '%':	push(opr1 % opr2, &top); break;
			}
		}
	}
	return pop(&top);
}

void test3()
{
	stackNode* top = NULL;
	int result;
	int i;
	char infix_expr[13][80] = { "3*5-6/2",
		"((4+2)/4)-(3+70/(7*5))",
		"((((5*6)+7)-8)*9)",
		"((((5*6)+7)-8)*9)+(9+8)*7",
		"((((5*6)+7)-8)*9)+(((9+8)*7)%4)",
		"(((((((((1*2)*3)*4)*5)*6)*7)*8)*9)*10)",
		"1*2+3*4+6/2+8%3+9-8",
		"70+80*9-10+(60+70+80*2-10)",
		"(9-(4/2+1))*(5*2-2)",
		"((80*87)/4)*2-705",
		"100*((90-80+20*5)-(30*20-10/5))",
		"(9-(4/2+1+(10*5)+7*6))*(50*20-10%2)",
		"123+456*(789+(90-80+20*5)-(30*20-10/5))", };
	char postfix_expr[320] = { 0x00, };

	for (i = 0; i < 13; i++)
	{
		printf("\n[%02d]-th 수식 평가\n", i);
		if (testPair(infix_expr[i], &top) == 1) {
			printf("괄호 개수가 일치함\n");
		}
		else {
			printf("괄호 개수가 불일치함\n");
		}

		memset(postfix_expr, 0, sizeof(postfix_expr));

		init(&top);
		infix_to_postfix(infix_expr[i], postfix_expr, top);

		printf("\n\ninfix: %s -> postfix: %s", infix_expr[i], postfix_expr);

		result = evalPostfix(postfix_expr, top);

		printf("\n\n연산 결과 => %d\n\n", result);

		freeStack(&top);
		getchar();
	}
}

int main()
{
	test1();
	//test2();
	//test3();

	getchar();
	return 0;
}