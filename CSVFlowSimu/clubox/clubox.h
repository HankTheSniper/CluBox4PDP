#ifndef __CLUBOX_H
#define __CLUBOX_H

#include <math.h>
#include <string.h>

#define ESP 20.0f
#define MINPTS 8
#define MAX_CLUSTER 50
#define BOX_LIVES 20

static inline float computeManhattanFloat(float *point0, float *point1, int dim)
{
    float dist = 0;
    for(int i = 0; i < dim; i++)
    {
        dist += fabsf(point0[i] - point1[i]);
        if (dist > ESP) return dist;
    }
    return dist;
}

static inline int computeManhattanInt(int *point0, int *point1, int dim)
{
    int dist = 0;
    for(int i = 0; i < dim; i++)
    {
        dist += abs(point0[i] - point1[i]);
    }
    return dist;
}

static inline void updateClusterBoxFloat(float *point, float *box, int dim)
{
    for(int d = 0; d < dim; d++)
    {
        if(point[d] < box[2 * d])
        {
            box[2 * d] = point[d];
        }
        if(point[d] > box[2 * d + 1])
        {
            box[2 * d + 1] = point[d];
        }
    }
}

static inline float computeBoxVolFloat(float *box, int dim)
{
    float volume = 1.0f;
    for(int d = 0; d < dim; d++)
    {
        volume *= box[2 * d + 1] - box[2 * d];
    }
    return volume;
}

static inline int computeBoxVolnt(int *box, int dim)
{
    int volume = 1;
    for(int d = 0; d < dim; d++)
    {
        volume *= box[2 * d + 1] - box[2 * d];
    }
    return volume;
}

static inline int* sortFloat(float *value, int val_count, char small2big)
{
    int *index = (int *)calloc(val_count, sizeof(int));
    int temp;
    for(int i = 0; i < val_count; i++)
    {
        index[i] = i;
    }
    for(int i = 0; i < val_count - 1; i++)
    {
        for(int j = 0; j < val_count - 1 - i; j++)
        {
            if(small2big)
            {
                if(value[index[j]] > value[index[j + 1]])
                {
                    temp = index[j];
                    index[j] = index[j + 1];
                    index[j + 1] = temp;
                }
            }
            else
            {
                if(value[index[j]] < value[index[j + 1]])
                {
                    temp = index[j];
                    index[j] = index[j + 1];
                    index[j + 1] = temp;
                }
            }
        }
    }
    return index;
}

static inline int* sortInt(int *value, int val_count, char small2big)
{
    int *index = (int *)calloc(val_count, sizeof(int));
    int temp;
    for(int i = 0; i < val_count; i++)
    {
        index[i] = i;
    }
    for(int i = 0; i < val_count - 1; i++)
    {
        for(int j = 0; j < val_count - 1 - i; j++)
        {
            if(small2big)
            {
                if(value[index[j]] > value[index[j + 1]])
                {
                    temp = index[j];
                    index[j] = index[j + 1];
                    index[j + 1] = temp;
                }
            }
            else
            {
                if(value[index[j]] < value[index[j + 1]])
                {
                    temp = index[j];
                    index[j] = index[j + 1];
                    index[j + 1] = temp;
                }
            }
        }
    }
    return index;
}

static inline float computeOverlapFloat(float *box0, float *box1, int dim)
{
    float overlap_vol = 1.0f;
    for(int d = 0; d < dim; d++)
    {
        float overlap_min = (box0[2 * d] > box1[2 * d]) ? box0[2 * d] : box1[2 * d];
        float overlap_max = (box0[2 * d + 1] < box1[2 * d + 1]) ? box0[2 * d + 1] : box1[2 * d + 1];

        if (overlap_min >= overlap_max)
        {
            return 0;
        }
        overlap_vol *= (overlap_max - overlap_min);
    }
    return overlap_vol;
}

static inline int computeOverlapInt(int *box0, int *box1, int dim)
{
    int overlap_vol = 1;
    for(int d = 0; d < dim; d++)
    {
        int overlap_min = (box0[2 * d] > box1[2 * d]) ? box0[2 * d] : box1[2 * d];
        int overlap_max = (box0[2 * d + 1] < box1[2 * d + 1]) ? box0[2 * d + 1] : box1[2 * d + 1];

        if (overlap_min >= overlap_max)
        {
            return 0;
        }
        overlap_vol *= (overlap_max - overlap_min);
    }
    return overlap_vol;
}

static inline char inBoxFloat(float *dot, float *box, int dim)
{
    for(int d = 0; d < dim; d++)
    {
        if(dot[d] < box[2 * d])
        {
            return 0;
        }
        if(dot[d] > box[2 * d + 1])
        {
            return 0;
        }
    }
    return 1;
}

static inline char inBoxInt(int *dot, int *box, int dim)
{
    for(int d = 0; d < dim; d++)
    {
        if(dot[d] < box[2 * d])
        {
            return 0;
        }
        if(dot[d] > box[2 * d + 1])
        {
            return 0;
        }
    }
    return 1;
}

static inline float computePolynomial(float w0, float *w, float *x, int dim)
{
    float result = w0;
    for(int d = 0; d < dim; d++)
    {
        result += w[d] * x[d];
    }
    return result;
}

static int deleteItems(void *items, int data_size, int len, int *del_idx, int del_count)
{
    char *ptr = (char *)items;
    int offset = 0;

    for(int i = 0; i < len; i++)
    {
        int is_del = 0;
        for(int j = 0; j < del_count; j++)
        {
            if(i == del_idx[j])
            {
                is_del = 1;
                break;
            }
        }

        if(is_del)
        {
            offset++;
        }
        else if(offset > 0)
        {
            memcpy(ptr + (i - offset) * data_size, ptr + i * data_size, data_size);
        }
    }
    return len - del_count;
}

int FlowDBScanFloat(float **data, int *data_size, int* cluster, float** c_box, int* c_count);
int FlowDBScanFloatPro(float **data, int *data_size, int* cluster, float** c_box, int* c_count);
int FlowDBScanInt(int **data, int *data_size, int* cluster, int** c_box, int* c_count);
char checkOverlapFloat(float** boxes, int box_count, int dim);
char checkOverlapInt(int** boxes, int box_count, int dim);
int checkPointBoxFloat(float *point, float **boxes, int *index, int dim, int k);
int checkPointBoxInt(int *point, int **boxes, int *index, int dim, int k);
char BoxBadDecisionTreeFloat(float *box);
void outputDbScanResultFloat(char** heads, int *size, float **float_data, char **label, int *points_cluster, int k, char* timeStr, char *moreInfo);
void outputDbScanBoxesFloat(float** boxes, int k, int dim, char* timeStr, char *moreInfo);

#endif /* __CLUBOX_H */
