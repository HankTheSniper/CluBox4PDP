#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <limits.h>
#include "./clubox.h"
#include "./stack.h"

float score_weight0 = -0.277025;
float score_weight[5] = {39.107995, -46.643548, 0.341166, -0.280435, 0.0f};

//float score_weight0 = -0.077025;
//float score_weight[5] = {39.107995, -46.643548, 0.341166, -0.280435, 0.0f};

//float score_weight0 = 6.842803;
//float score_weight[5] = {41.367532, -49.538457, 0.450111, -0.292035, -7.421655};

//float score_weight0 = 5.842803;
//float score_weight[5] = {41.367532, -49.538457, 0.450111, -0.292035, -7.421655};

//float score_weight0 = -1.342467;
//float score_weight[6] = {40.868040, -1.179667, 0.054382, 1.221989, -1.436131, -45.168997};

//float score_weight0 = -10.1073;
//float score_weight[6] = {25.9108, -1.9454, 0.0215, 2.0450, 6.3369, -28.4725};

int FlowDBScanFloat(float **data, int *data_size, int* cluster, float** c_box, int* c_count)
{
    int row = data_size[0];
    int dim = data_size[1];
    int k = 0;
    int t = 0;
    float dist = -1.0f;
    int *neibor_count = malloc(row * sizeof(int));
    SeqStack *points_check = new_SeqStack;
    initStack(points_check);

    for(int i = 0; i < row; i++)
    {
        cluster[i] = -2;
        neibor_count[i] = 1;
    }
    for(int i = 0; i < MAX_CLUSTER; i++)
    {
        c_box[i] = (float *)calloc(dim * 2, sizeof(float));
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
            dist = computeManhattanFloat(data[i], data[j], dim);
            if(dist <= ESP)
            {
                neibor_count[i]++;
                neibor_count[j]++;
            }
        }
    }
    for(int i = 0; i < row; i++)
    {
        if(neibor_count[i] >= MINPTS && cluster[i] == -2)
        {
            cluster[i] = k;
            c_count[k]++;
            for(int d = 0; d < dim; d++)
            {
                c_box[k][2 * d] = (data[i][d] < c_box[k][2 * d])?data[i][d]:c_box[k][2 * d];
                c_box[k][2 * d + 1] = (data[i][d] > c_box[k][2 * d + 1])?data[i][d]:c_box[k][2 * d + 1];
                c_box[k][2 * d + 1] = (c_box[k][2 * d + 1] == c_box[k][2 * d])?(c_box[k][2 * d + 1] + 1):c_box[k][2 * d + 1];
            }
            push(points_check, i);
            while(getElemCount(points_check) > 0)
            {
                t = pop(points_check);
                for(int j = 0; j < row; j++)
                {
                    dist = computeManhattanFloat(data[t], data[j], dim);
                    if(dist <= ESP && cluster[j] < 0)
                    {
                        cluster[j] = k;
                        c_count[k]++;
                        for(int d = 0; d < dim; d++)
                        {
                            c_box[k][2 * d] = (data[j][d] < c_box[k][2 * d])?data[j][d]:c_box[k][2 * d];
                            c_box[k][2 * d + 1] = (data[j][d] > c_box[k][2 * d + 1])?data[j][d]:c_box[k][2 * d + 1];
                            c_box[k][2 * d + 1] = (c_box[k][2 * d + 1] == c_box[k][2 * d])?(c_box[k][2 * d + 1] + 1):c_box[k][2 * d + 1];
                        }
                        if(neibor_count[j] >= MINPTS)
                        {
                            push(points_check, j);
                        }
                    }
                }
            }
            k++;
        }
        else if(neibor_count[i] < MINPTS && cluster[i] == -2)
        {
            cluster[i] = -1;
        }
    }

    return k;
}

int FlowDBScanFloatPro(float **data, int *data_size, int* cluster, float** c_box, int* c_count)
{
    int row = data_size[0];
    int dim = data_size[1];
    int k = 0;
    int t, t_nei;
    float dist;
    int *neibor_count = (int *)calloc(row, sizeof(int));
    int *neibor_point = (int *)calloc(row * row, sizeof(int));
    SeqStack *points_check = new_SeqStack;
    initStack(points_check);

    for(int i = 0; i < row; i++)
    {
        cluster[i] = -2;
    }
    for(int i = 0; i < MAX_CLUSTER; i++)
    {
        c_box[i] = (float *)calloc(dim * 2, sizeof(float));
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
            dist = computeManhattanFloat(data[i], data[j], dim);
            if(dist <= ESP)
            {
                neibor_point[i * row + neibor_count[i]] = j;
                neibor_point[j * row + neibor_count[j]] = i;
                neibor_count[i]++;
                neibor_count[j]++;
            }
        }
    }
    for(int i = 0; i < row; i++)
    {
        if(neibor_count[i] + 1 >= MINPTS && cluster[i] == -2)
        {
            cluster[i] = k;
            c_count[k]++;
            push(points_check, i);
            while(getElemCount(points_check) > 0)
            {
                t = pop(points_check);
                for(int j = 0; j < neibor_count[t]; j++)
                {
                    t_nei = neibor_point[t * row + j];
                    if(cluster[t_nei] == -2)
                    {
                        cluster[t_nei] = k;
                        c_count[k]++;
                        if(neibor_count[t_nei] + 1 >= MINPTS)
                        {
                            push(points_check, t_nei);
                        }
                    }
                    else if(cluster[t_nei] == -1)
                    {
                        cluster[t_nei] = k;
                        c_count[k]++;
                    }
                }
            }
            k++;
        }
        else if(neibor_count[i] + 1 < MINPTS && cluster[i] == -2)
        {
            cluster[i] = -1;
        }
    }
    for(int i = 0; i < row; i++)
    {
        int k_index = cluster[i];
        if(k_index >= 0)
        {
            updateClusterBoxFloat(data[i], c_box[k_index], dim);
        }
    }
    for(int i = 0; i < k; i++) {
        for(int d = 0; d < dim; d++) {
            if(c_box[i][2 * d + 1] == c_box[i][2 * d]) {
                c_box[i][2 * d + 1] += 1.0f;
            }
        }
    }
    free(neibor_count);
    free(neibor_point);
    return k;
}

int FlowDBScanFloatFast(float *data, int *data_size, int* cluster, float** c_box, int* c_count)
{
    int row = data_size[0];
    int dim = data_size[1];
    int k = 0;
    int t, t_nei;
    float dist;
    int *neibor_count = (int *)calloc(row, sizeof(int));
    int *neibor_point = (int *)calloc(row * row, sizeof(int));
    SeqStack *points_check = new_SeqStack;
    initStack(points_check);

    for(int i = 0; i < row; i++)
    {
        cluster[i] = -2;
    }
    for(int i = 0; i < MAX_CLUSTER; i++)
    {
        c_box[i] = (float *)calloc(dim * 2, sizeof(float));
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
                neibor_point[i * row + neibor_count[i]] = j;
                neibor_point[j * row + neibor_count[j]] = i;
                neibor_count[i]++;
                neibor_count[j]++;
            }
        }
    }
    for(int i = 0; i < row; i++)
    {
        if(neibor_count[i] + 1 >= MINPTS && cluster[i] == -2)
        {
            cluster[i] = k;
            c_count[k]++;
            push(points_check, i);
            while(getElemCount(points_check) > 0)
            {
                t = pop(points_check);
                for(int j = 0; j < neibor_count[t]; j++)
                {
                    t_nei = neibor_point[t * row + j];
                    if(cluster[t_nei] == -2)
                    {
                        cluster[t_nei] = k;
                        c_count[k]++;
                        if(neibor_count[t_nei] + 1 >= MINPTS)
                        {
                            push(points_check, t_nei);
                        }
                    }
                    else if(cluster[t_nei] == -1)
                    {
                        cluster[t_nei] = k;
                        c_count[k]++;
                    }
                }
            }
            k++;
        }
        else if(neibor_count[i] + 1 < MINPTS && cluster[i] == -2)
        {
            cluster[i] = -1;
        }
    }
    for(int i = 0; i < row; i++)
    {
        int k_index = cluster[i];
        if(k_index >= 0)
        {
            updateClusterBoxFloat(&data[i * dim], c_box[k_index], dim);
        }
    }
    for(int i = 0; i < k; i++) {
        for(int d = 0; d < dim; d++) {
            if(c_box[i][2 * d + 1] == c_box[i][2 * d]) {
                c_box[i][2 * d + 1] += 1.0f;
            }
        }
    }
    free(neibor_count);
    free(neibor_point);
    destroyStack(points_check);
    return k;
}

int FlowDBScanInt(int **data, int *data_size, int* cluster, int** c_box, int* c_count)
{
    int row = data_size[0];
    int dim = data_size[1];
    int k = 0;
    int t = 0;
    int dist = -1.0f;
    int *neibor_count = malloc(row * sizeof(int));;
    SeqStack *points_check = new_SeqStack;
    initStack(points_check);

    for(int i = 0; i < row; i++)
    {
        cluster[i] = -2;
        neibor_count[i] = 1;
    }
    for(int i = 0; i < MAX_CLUSTER; i++)
    {
        if(c_box[i] == NULL)
        {
            c_box[i] = (int *)calloc(dim * 2, sizeof(int));
        }
        for(int d = 0; d < dim; d++)
        {
            c_box[i][2 * d] = INT_MAX;
            c_box[i][2 * d + 1] = 0;
        }
    }

    for(int i = 0; i < row - 1; i++)
    {
        for(int j = i + 1; j < row; j++)
        {
            dist = computeManhattanInt(data[i], data[j], dim);
            if(dist <= ESP)
            {
                neibor_count[i]++;
                neibor_count[j]++;
            }
        }
    }
    for(int i = 0; i < row; i++)
    {
        if(neibor_count[i] >= MINPTS && cluster[i] == -2)
        {
            cluster[i] = k;
            c_count[k]++;
            for(int d = 0; d < dim; d++)
            {
                c_box[k][2 * d] = (data[i][d] < c_box[k][2 * d])?data[i][d]:c_box[k][2 * d];
                c_box[k][2 * d + 1] = (data[i][d] > c_box[k][2 * d + 1])?data[i][d]:c_box[k][2 * d + 1];
                c_box[k][2 * d + 1] = (c_box[k][2 * d + 1] == c_box[k][2 * d])?(c_box[k][2 * d + 1] + 1):c_box[k][2 * d + 1];
            }
            push(points_check, i);
            while(getElemCount(points_check) > 0)
            {
                t = pop(points_check);
                for(int j = 0; j < row; j++)
                {
                    dist = computeManhattanInt(data[t], data[j], dim);
                    if(dist <= ESP && cluster[j] < 0)
                    {
                        cluster[j] = k;
                        c_count[k]++;
                        for(int d = 0; d < dim; d++)
                        {
                            c_box[k][2 * d] = (data[j][d] < c_box[k][2 * d])?data[j][d]:c_box[k][2 * d];
                            c_box[k][2 * d + 1] = (data[j][d] > c_box[k][2 * d + 1])?data[j][d]:c_box[k][2 * d + 1];
                            c_box[k][2 * d + 1] = (c_box[k][2 * d + 1] == c_box[k][2 * d])?(c_box[k][2 * d + 1] + 1):c_box[k][2 * d + 1];
                        }
                        if(neibor_count[j] >= MINPTS)
                        {
                            push(points_check, j);
                        }
                    }
                }
            }
            k++;
        }
        else if(neibor_count[i] < MINPTS && cluster[i] == -2)
        {
            cluster[i] = -1;
        }
    }

    return k;
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

char BoxBadDecisionTreeFloat(float *box)
{
    if(box[0 * 2 + 1] > 75.25)
    {
        return 1;
    }
    else
    {
        if(box[1 * 2 + 1] > 557.67)
        {
            return 1;
        }
        else
        {
            if(box[1 * 2] > 124.67)
            {
                return 0;
            }
            else
            {
                if(box[1 * 2 + 1] > 61.37)
                {
                    return 1;
                }
                else
                {
                    return 0;
                }
            }
        }
    }
}

char statisticConfusionMat(int **mat, char *label, char *good_label, int result)
{
    if(!strcmp(label, good_label) && result == 0)
    {
        (*mat)[0]++;
        return 1;
    }
    else if(strcmp(label, good_label) && result == 1)
    {
        (*mat)[1]++;
        return 1;
    }
    else if(!strcmp(label, good_label) && result == 1)
    {
        (*mat)[2]++;
        return 0;
    }
    else if(strcmp(label, good_label) && result == 0)
    {
        (*mat)[3]++;
        return 0;
    }
}

void printSliceStatistiacalData(int *mat) {
    float tp = (float)mat[0];
    float tn = (float)mat[1];
    float fn = (float)mat[2];
    float fp = (float)mat[3];

    float total = tp + tn + fp + fn;

    float accuracy  = (total > 0.0f) ? (tp + tn) / total : 0.0f;
    float precision = (tp + fp > 0.0f) ? tp / (tp + fp) : 0.0f;
    float recall    = (tp + fn > 0.0f) ? tp / (tp + fn) : 0.0f;
    float f1        = (precision + recall > 0.0f) ? 2.0f * (precision * recall) / (precision + recall) : 0.0f;

    printf("\n---------------- Confusion Matrix ----------------\n");
    printf("Confusion Matrix:\n");
    printf("             [Pred:Pos]  [Pred:Neg]\n");
    printf("[Actual:Pos]    %-5d       %-5d    (TP/FN)\n", (int)tp, (int)fn);
    printf("[Actual:Neg]    %-5d       %-5d    (FP/TN)\n", (int)fp, (int)tn);
    printf("\n------------------- Statistics -------------------\n");
    printf("Accuracy:  %.2f%%\n", accuracy * 100.0f);
    printf("Precision: %.2f%%\n", precision * 100.0f);
    printf("Recall:    %.2f%%\n", recall * 100.0f);
    printf("F1 Score:  %.4f\n", f1);
    printf("----------------------------------------------------\n\n");
}

void printStatistiacalData(int **mats, int slice_count) {
    float tp = 0;
    float tn = 0;
    float fn = 0;
    float fp = 0;

    for(int slice_index = 0; slice_index < slice_count; slice_index++)
    {
        tp += (float)mats[slice_index][0];
        tn += (float)mats[slice_index][1];
        fn += (float)mats[slice_index][2];
        fp += (float)mats[slice_index][3];
    }

    float total = tp + tn + fp + fn;

    float accuracy  = (total > 0.0f) ? (tp + tn) / total : 0.0f;
    float precision = (tp + fp > 0.0f) ? tp / (tp + fp) : 0.0f;
    float recall    = (tp + fn > 0.0f) ? tp / (tp + fn) : 0.0f;
    float f1        = (precision + recall > 0.0f) ? 2.0f * (precision * recall) / (precision + recall) : 0.0f;

    printf("\n================= Confusion Matrix =================\n");
    printf("Confusion Matrix:\n");
    printf("             [Pred:Pos]  [Pred:Neg]\n");
    printf("[Actual:Pos]    %-5d       %-5d    (TP/FN)\n", (int)tp, (int)fn);
    printf("[Actual:Neg]    %-5d       %-5d    (FP/TN)\n", (int)fp, (int)tn);
    printf("\n==================== Statistics ====================\n");
    printf("Accuracy:  %.2f%%\n", accuracy * 100.0f);
    printf("Precision: %.2f%%\n", precision * 100.0f);
    printf("Recall:    %.2f%%\n", recall * 100.0f);
    printf("F1 Score:  %.4f\n", f1);
    printf("=====================================================\n\n");
}

#include <stdio.h>

void outputStatisticsToCSV(const char *filename, int **mats, int slice_count) {
    FILE *fp_file = fopen(filename, "w");
    if (fp_file == NULL) {
        printf("Error: Could not open file %s for writing.\n", filename);
        return;
    }

    fprintf(fp_file, "Slice,TP,TN,FN,FP,Accuracy,Precision,Recall,F1\n");

    float total_tp = 0, total_tn = 0, total_fn = 0, total_fp = 0;

    for (int i = 0; i < slice_count; i++) {
        float tp = (float)mats[i][0];
        float tn = (float)mats[i][1];
        float fn = (float)mats[i][2];
        float fp = (float)mats[i][3];

        float total = tp + tn + fp + fn;
        float acc = (total > 0.0f) ? (tp + tn) / total : 0.0f;
        float pre = (tp + fp > 0.0f) ? tp / (tp + fp) : 0.0f;
        float rec = (tp + fn > 0.0f) ? tp / (tp + fn) : 0.0f;
        float f1  = (pre + rec > 0.0f) ? 2.0f * (pre * rec) / (pre + rec) : 0.0f;

        fprintf(fp_file, "%d,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.4f\n",
                i, (int)tp, (int)tn, (int)fn, (int)fp, acc, pre, rec, f1);

        total_tp += tp; total_tn += tn; total_fn += fn; total_fp += fp;
    }

    float g_total = total_tp + total_tn + total_fn + total_fp;
    float g_acc = (g_total > 0.0f) ? (total_tp + total_tn) / g_total : 0.0f;
    float g_pre = (total_tp + total_fp > 0.0f) ? total_tp / (total_tp + total_fp) : 0.0f;
    float g_rec = (total_tp + total_fn > 0.0f) ? total_tp / (total_tp + total_fn) : 0.0f;
    float g_f1  = (g_pre + g_rec > 0.0f) ? 2.0f * (g_pre * g_rec) / (g_pre + g_rec) : 0.0f;

    fprintf(fp_file, "TOTAL,%d,%d,%d,%d,%.4f,%.4f,%.4f,%.4f\n",
            (int)total_tp, (int)total_tn, (int)total_fn, (int)total_fp, g_acc, g_pre, g_rec, g_f1);

    fclose(fp_file);
    printf("[+] Statistics saved to %s successfully.\n", filename);
}

void outputDbScanResultFloat(char** heads, int *size, float **float_data, char **label, int *points_cluster, int k, char* timeStr, char *moreInfo)
{
    char filename[512];
    snprintf(filename, sizeof(filename), "./data/new_result/%s_dbscan_%.2f_%d_%spoints.csv", timeStr, ESP, MINPTS, moreInfo);

    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        printf("[-] Fail to make the result file\n");
        return;
    }

    for(int i = 0; i < size[1]; i++)
    {
        fprintf(file, "%s,", heads[i]);
    }
    fprintf(file, "Label,Cluster");
    fprintf(file, "\n");
    for(int i = 0; i < size[0]; i++)
    {
        for(int j = 0; j < size[1]; j++)
        {
            fprintf(file, "%f,", float_data[i][j]);
        }
        fprintf(file, "%s,%d", label[i], points_cluster[i]);
        fprintf(file, "\n");
    }
    fclose(file);
}

void outputDbScanBoxesFloat(float** boxes, int k, int dim, char* timeStr, char* moreInfo)
{
    char filename[512];
    snprintf(filename, sizeof(filename), "./data/new_result/%s_dbscan_%.2f_%d_%sboxes.csv", timeStr, ESP, MINPTS, moreInfo);
    FILE *file = fopen(filename, "w");

    if (file == NULL) {
        printf("[-] Fail to make the result file: %s, Error: %s\n", filename, strerror(errno));
        return;
    }
    for(int i = 0; i < k; i++)
    {
        fprintf(file, "%d", i);
        for(int j = 0; j < dim; j++)
        {
            fprintf(file, ",%f,%f", boxes[i][j * 2], boxes[i][j * 2 + 1]);
        }
        fprintf(file, "\n");
    }

    fclose(file);
}
