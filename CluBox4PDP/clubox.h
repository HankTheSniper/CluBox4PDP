#ifndef __CLUBOX_H
#define __CLUBOX_H

#include <math.h>
#include <rte_malloc.h>
#include <stdlib.h>

#define ESP 20.0f
#define MINPTS 10
#define MAX_CLUSTER 50
#define BOX_LIVES 20

extern struct box_model *local_box_model[2];
extern uint8_t active_box_model;
extern struct rte_ring *box_ring;

struct box_model
{
    float **boxes;
    int *order_index;
    int *box_points;
    float *box_volumes;
    int box_count;
    /* evaluation fields */
    int   *box_labels;        /* 0=benign, 1=malicious (placeholder until model trained) */
    float *box_scores;        /* combined spatial+meta score, for CSV logging */
    int   *prev_box_points;   /* box_points from previous window, for delta meta-feature */
    /* training data collection */
    int   *box_attack_count;  /* flows with attack IP assigned to this box */
    int   *box_benign_count;  /* flows with benign IP assigned to this box */
};

static inline float computeManhattanFloat(float *point0, float *point1, int dim)
{
    float dist = 0;
    for(int i = 0; i < dim; i++)
    {
        dist += fabs(point0[i] - point1[i]);
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

static inline char inBoxFloat(float *point, float *box, int dim)
{
    for(int d = 0; d < dim; d++)
    {
        if(point[d] < box[2 * d] || point[d] > box[2 * d + 1])
        {
            return 0;
        }
    }
    return 1;
}

static inline char inBoxInt(int *point, int *box, int dim)
{
    for(int d = 0; d < dim; d++)
    {
        if(point[d] < box[2 * d] || point[d] > box[2 * d + 1])
        {
            return 0;
        }
    }
    return 1;
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

void initBoxes(void);
int CluBoxFloat(float *data, int row, int dim, int *points_cluster, float **c_box, int *c_count);
int checkPointBoxFloat(float *point, float **boxes, int *index, int dim, int k);
int checkPointBoxInt(int *point, int **boxes, int *index, int dim, int k);
char checkOverlapFloat(float** boxes, int box_count, int dim);
char checkOverlapInt(int** boxes, int box_count, int dim);
struct box_model **getBoxModelReference(uint8_t idx); 
#endif /* __CLUBOX_H */
