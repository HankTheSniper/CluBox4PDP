#ifndef __STACK_H
#define __STACK_H

#define Stack_Size 20000
#define new_SeqStack (SeqStack*)malloc(sizeof(SeqStack))

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef struct
{
    int elem[Stack_Size];
    int top;
}SeqStack;

void initStack(SeqStack *S)
{
    S->top=-1;
}

void push(SeqStack *S,int x)
{
    assert(S->top!=Stack_Size-1);
    if(S->top!=Stack_Size-1)
    {
        S->top++;
        S->elem[S->top]=x;
    }

}

int pop(SeqStack *S)
{
    int x;
    assert(S->top!=-1);
    if(S->top!=-1)
    {
        x=S->elem[S->top];
        S->top--;
    }
    return x;
}

int getTop(SeqStack *S)
{
    int x;
    assert(S->top!=-1);
    if(S->top!=-1)
    {
        x=S->elem[S->top];
    }
    return x;
}

int getElemCount(SeqStack *S)
{
    return S->top + 1;
}

void destroyStack(SeqStack *S)
{
    free(S);
}

#endif /* __STACK_H */
