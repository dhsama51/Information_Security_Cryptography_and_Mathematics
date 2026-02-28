#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#define MAX_STR 20
#define MAX_MEANING 40

#define MAX(a,b) ((a>b)?a:b)

// 자료구조 정의
typedef struct _DATA_ {
	char word[MAX_STR]; // 단어(spelling)
	char meaning[MAX_MEANING];// 의미
}DATA;

typedef struct _TREENODE_ {
	struct _DATA_ key;
	struct _TREENODE_* left;
	struct _TREENODE_* right;
}TREENODE;

int getHeight(TREENODE* p) {
	int height = 0;
	if (p != NULL) height = MAX(getHeight(p->left), getHeight(p->right)) + 1;
	return height;
}

TREENODE* searchNode(TREENODE* root, char* x) {
	TREENODE* p = NULL;
	int count = 0;

	p = root;
	while (p != NULL) {

		count++;		// 검색횟수 파악

		if (strcmp(x, p->key.word) < 0) p = p->left;
		else if (strcmp(x, p->key.word) == 0)
		{
			printf("%s,   %3d번째에 탐색 성공", x, count);
			return p;
		}
		else p = p->right;
	}
	count++;

	printf("\n %3d번째에 탐색 실패, 찾는 키가 없습니다.!\n", count);
	return p;
}

TREENODE* LL_rotate(TREENODE* parent) {
	TREENODE* child = parent->left;
	parent->left = child->right;
	child->right = parent;
	return child;
}

TREENODE* RR_rotate(TREENODE* parent) {
	TREENODE* child = parent->right;
	parent->right = child->left;
	child->left = parent;
	return child;
}

TREENODE* LR_rotate(TREENODE* parent) {
	TREENODE* child = parent->left;
	parent->left = RR_rotate(child);
	return LL_rotate(parent);
}

TREENODE* RL_rotate(TREENODE* parent) {
	TREENODE* child = parent->right;
	parent->right = LL_rotate(child);
	return RR_rotate(parent);
}

int getBF(TREENODE* p) {
	if (p == NULL) {
		return 0;
	}
	return getHeight(p->left) - getHeight(p->right);
}

TREENODE* rebalance(TREENODE** p)
{
	int BF = getBF(*p);
	
	if (BF > 1)
	{
		if (getBF((*p)->left) >= 0) *p = LL_rotate(*p);
		else *p = LR_rotate(*p);
	}
	
	else if (BF < -1)
	{
		if (getBF((*p)->right) <= 0) *p = RR_rotate(*p);
		else *p = RL_rotate(*p);
	}
	return *p;
}

TREENODE* insert_AVL_Node(TREENODE** root, DATA* x)
{
	if (x->word == "")
	{
		return;
	}
	if (*root == NULL)
	{
		*root = (TREENODE*)calloc(1, sizeof(TREENODE));
		memset((*root)->key.word, 0, 29);
		memset((*root)->key.meaning, 0, 39);
		strcpy(((*root)->key).word, x->word);
		strcpy(((*root)->key).meaning, x->meaning);
		(*root)->left = NULL;
		(*root)->right = NULL;
	}
	else if (strcmp(x->word, ((*root)->key).word) < 0)
	{
		(*root)->left = insert_AVL_Node(&((*root)->left), x);
		*root = rebalance(root);
	}
	else if (strcmp(x->word, ((*root)->key).word) > 0)
	{
		(*root)->right = insert_AVL_Node(&((*root)->right), x);
		*root = rebalance(root);
	}
	else {
		printf("\n이미 같은 키가 있습니다.\n");
		return NULL;
	}
	return *root;
}

void fprintfInorder(FILE* g, TREENODE* root) {
	if (root) {
		fprintfInorder(g, root->left);
		fprintf(g, "%s %s\n", (*root).key.word, (*root).key.meaning);
		fprintfInorder(g, root->right);
	}
}

void displayInorder(TREENODE* root) {
	if (root) {
		displayInorder(root->left);
		printf("%s, %s\n", root->key.word, root->key.meaning);
		displayInorder(root->right);
	}
}

void test1()
{
	int i = 0;
	int meaningFlag = 1, wordFlag = -1;
	char buf[30] = { 0, };
	TREENODE* AVL = NULL;
	DATA* input = (DATA*)calloc(1, sizeof(DATA));

	// voca.txt 파일을 읽으면서 AVL 트리 구성
	FILE* f = fopen("voca.txt", "r");

	while(EOF != fscanf(f, "%s", buf))
	{
		if ((buf[0] >= 'a' && buf[0] <= 'z') || (buf[0] >= 'A' && buf[0] <= 'Z'))
		{
			if (wordFlag == -1)
			{
				memset((*input).word, 0, 29);
				strcpy(input->word, buf);
				wordFlag = 0;
				meaningFlag = 1;
			}

			else if (wordFlag == 0)
			{
				strcat((*input).word, " ");
				strcat((*input).word, buf);
				meaningFlag = 1;
			}

			else
			{
				insert_AVL_Node(&AVL, input);
				memset((*input).word, 0, 29);
				strcpy(input->word, buf);
				wordFlag = 0;
				meaningFlag = 1;
			}
		}
		else
		{
			if(meaningFlag == 0)
			{
				strcat((*input).meaning, " ");
				strcat((*input).meaning, buf);
				wordFlag = 1;
			}

			else
			{
				memset((*input).meaning, 0, 29);
				strcat((*input).meaning, buf);
				meaningFlag = 0;
				wordFlag = 1;
			}
		}
	}

	fclose(f);

	// 10개의 단어에 대해 검색
	searchNode(AVL, "culture");
	printf("\n");
	searchNode(AVL, "experience");
	printf("\n");
	searchNode(AVL, "liberty");
	printf("\n");
	searchNode(AVL, "tradition");
	printf("\n");
	searchNode(AVL, "revolution");
	printf("\n");
	searchNode(AVL, "pollution");
	printf("\n");
	searchNode(AVL, "figure");
	printf("\n");
	searchNode(AVL, "view");
	printf("\n");
	searchNode(AVL, "monument");
	printf("\n");
	searchNode(AVL, "appointment");

	// 오름차순으로 정렬된 형태로 파일에 기록(ordered_voca.txt)
	FILE* g = fopen("ordered_voca.txt", "w");
	fprintfInorder(g, AVL);
	fclose(g);
}

int main()
{
	test1();

	getchar();
	return 0;
}