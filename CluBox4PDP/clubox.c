#include "clubox.h"
#include "pseudo_flow.h"
#include "stack.h"

struct box_model *local_box_model[2];
uint8_t active_box_model = 0;
struct rte_ring *box_ring = NULL;

void initBoxes()
{
    for(int idx = 0; idx < 2; idx++)
    {
        if (local_box_model[idx] == NULL)
        {
            local_box_model[idx] = rte_zmalloc("box_model_struct", sizeof(struct box_model), 64);
        }
        if (local_box_model[idx])
        {
            local_box_model[idx]->order_index    = rte_zmalloc("order_index",    MAX_CLUSTER * sizeof(int),   64);
            local_box_model[idx]->box_points     = rte_zmalloc("box_points",     MAX_CLUSTER * sizeof(int),   64);
            local_box_model[idx]->box_volumes    = rte_zmalloc("box_volumes",    MAX_CLUSTER * sizeof(float), 64);
            local_box_model[idx]->boxes          = rte_zmalloc("boxes_ptrs",     MAX_CLUSTER * sizeof(float *), 64);
            local_box_model[idx]->box_labels     = rte_zmalloc("box_labels",     MAX_CLUSTER * sizeof(int),   64);
            local_box_model[idx]->box_scores     = rte_zmalloc("box_scores",     MAX_CLUSTER * sizeof(float), 64);
            local_box_model[idx]->prev_box_points= rte_zmalloc("prev_box_pts",   MAX_CLUSTER * sizeof(int),   64);
            local_box_model[idx]->box_attack_count = rte_zmalloc("box_atk_cnt", MAX_CLUSTER * sizeof(int),   64);
            local_box_model[idx]->box_benign_count = rte_zmalloc("box_ben_cnt", MAX_CLUSTER * sizeof(int),   64);
            for (int i = 0; i < MAX_CLUSTER; i++)
            {
                local_box_model[idx]->boxes[i] = rte_zmalloc("box_coords", FEATURE_DIM * 2 * sizeof(float), 64);
            }
            local_box_model[idx]->box_count = 0;
        }
    }
    active_box_model = 0;
    printf("[Control Plane] Double buffered box models initialized.\n");
}

struct box_model **getBoxModelReference(uint8_t index)
{
    return &local_box_model[index]; 
}

int CluBoxFloat(float *data, int row, int dim, int *points_cluster, float **c_box, int *c_count)
{
    int cluster_count = 0;

    float dist = -1.0f;
    int *neighbor_count = (int *)calloc(row, sizeof(int));
    int *neighbor_point = (int *)calloc(row * row, sizeof(int));

    int t, t_nei;

    SeqStack *points_check = new_SeqStack;
    initStack(points_check);

    for(int i = 0; i < row; i++)
    {
        points_cluster[i] = -2;
    }
    for(int i = 0; i < MAX_CLUSTER; i++)
    {
        for(int d = 0; d < dim; d++)
        {
            c_box[i][2 * d] = INFINITY;
            c_box[i][2 * d + 1] = 0;
        }
    }
    for(int i = 0; i < row - 1; i++)
    {
        for(int j = i + 1; j < row; j++)
        {
            dist = computeManhattanFloat(&data[i * dim], &data[j * dim], dim);
            if(dist <= ESP)
            {
                neighbor_point[i * row + neighbor_count[i]] = j;
                neighbor_point[j * row + neighbor_count[j]] = i;
                neighbor_count[i]++;
                neighbor_count[j]++;
            }
        }
    }

    for(int i = 0; i < row; i++)
    {
        if(neighbor_count[i] + 1 >= MINPTS && points_cluster[i] == -2)
        {
            points_cluster[i] = cluster_count;
            c_count[cluster_count]++;
            push(points_check, i);
            while(getElemCount(points_check) > 0)
            {
                t = pop(points_check);
                for(int j = 0; j < neighbor_count[t]; j++)
                {
                    t_nei = neighbor_point[t * row + j];
                    if(points_cluster[t_nei] == -2)
                    {
                        points_cluster[t_nei] = cluster_count;
                        c_count[cluster_count]++;
                        if(neighbor_count[t_nei] + 1 >= MINPTS)
                        {
                            push(points_check, t_nei);
                        }
                    }
                    else if(points_cluster[t_nei] == -1)
                    {
                        points_cluster[t_nei] = cluster_count;
                        c_count[cluster_count]++;
                    }
                }
            }
            cluster_count++;
        }
        else if(neighbor_count[i] + 1 < MINPTS && points_cluster[i] == -2)
        {
            points_cluster[i] = -1;
        }
    }
    for(int i = 0; i < row; i++)
    {
        int cluster_index = points_cluster[i];
        if(cluster_index >= 0)
        {
            updateClusterBoxFloat(&data[i * dim], c_box[cluster_index], dim);
        }
    }
    for(int i = 0; i < cluster_count; i++)
    {
        for(int d = 0; d < dim; d++)
        {
            if(c_box[i][2 * d + 1] == c_box[i][2 * d])
            {
                c_box[i][2 * d + 1] += 1.0f;
            }
        }
    }
    
    free(neighbor_count);
    free(neighbor_point);
    destroyStack(points_check);

    return cluster_count;
}

int checkPointBoxFloat(float *point, float **boxes, int *index, int dim, int k)
{
    for(int i = 0; i < k; i++)
    {
        if(inBoxFloat(point, boxes[index[i]], dim))
        {
            return index[i];
        }
    }
    return -1;
}

int checkPointBoxInt(int *point, int **boxes, int *index, int dim, int k)
{
    for(int i = 0; i < k; i++)
    {
        if(inBoxInt(point, boxes[index[i]], dim))
        {
            return index[i];
        }
    }
    return -1;
}

char checkOverlapFloat(float** boxes, int box_count, int dim)
{
    for(int i = 0; i < box_count - 1; i++)
    {
        for(int j = i + 1; j < box_count; j++)
        {
            if(computeOverlapFloat(boxes[i], boxes[j], dim) > 0)
            {
                return 1;
            }
        }
    }
    return 0;
}

char checkOverlapInt(int** boxes, int box_count, int dim)
{
    for(int i = 0; i < box_count - 1; i++)
    {
        for(int j = i + 1; j < box_count; j++)
        {
            if(computeOverlapInt(boxes[i], boxes[j], dim) > 0)
            {
                return 1;
            }
        }
    }
    return 0;
}