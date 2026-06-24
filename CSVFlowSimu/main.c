#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <windows.h>
#include "clubox/clubox.h"
#include "simu/simu.h"

#define META_FEATURE_USE 1
#define SPACE_FEATURE_USE 1

int main()
{
    printInstruction();
    const char data_folder[30] = "data/data_processed/";
    const char search_pattern[10] = "*.csv";
    char data_path[80];
    sprintf(data_path, "%s%s", data_folder, search_pattern);

    srand(time(NULL));
    clock_t start, end;
    time_t rawtime;
    time(&rawtime);
    char timeStr[80];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d-%H-%M-%S", localtime(&rawtime));
    int over = 0;

    int k = 0;
    int *iter;
    float **boxes = (float **)calloc(MAX_CLUSTER, sizeof(float *));
    int boxes_result[MAX_CLUSTER];
    int boxes_count[MAX_CLUSTER] = {0};
    float boxes_volume[MAX_CLUSTER] = {0};
    float **boxes_meta = (float **)calloc(MAX_CLUSTER, sizeof(float *));
    float boxes_score[MAX_CLUSTER];
    float boxes_meta_score[MAX_CLUSTER];
    float boxes_space_score[MAX_CLUSTER];
    for(int i = 0; i < MAX_CLUSTER; i++)
    {
        boxes_meta[i] = (float *)calloc(8, sizeof(float));
        boxes_result[i] = -1;
    }
//    int boxes_benign_count[MAX_CLUSTER] = {0};
    extern float score_weight0;
    extern float score_weight[5];
    char Overlap = 0;
    int slice_accumu = 0;

    while(!over)
    {
        char *class_array[26];
        int class_count = getDataFolder(data_folder, (char **)class_array);

        void ***raw_data_array = (void ***)calloc(class_count, sizeof(void **));
        char ***labels_array = (char ***)calloc(class_count, sizeof(char **));
        char **heads = (char **)calloc(MAX_FIELDS, sizeof(char *));
        int **data_size_array = (int **)calloc(class_count, sizeof(int *));

        char *slices[TRAFFIC_MAX_SLICE];

        int slice_traffic_count[TRAFFIC_MAX_SLICE];
        int *slice_class_traffic_count[TRAFFIC_MAX_SLICE];
        int slice_index = 0;
        int slice_count = inputSlices(slices, data_folder, class_count, class_array, slice_traffic_count, slice_class_traffic_count, heads, raw_data_array, labels_array, data_size_array);
        int **slice_confusion_mat = (int **)calloc(slice_count, sizeof(int *));
//        strcpy(heads[0], "12.77 x (Pkt Len Max)^0.3");
        strcpy(heads[1], "75 x Lg(IAT Max + 1)");
        for(slice_index = 0; slice_index < slice_count; slice_index++)
        {
            void **traffic_temp = (void **)calloc(slice_traffic_count[slice_index], sizeof(void *));
            char **traffic_labels = (char **)calloc(slice_traffic_count[slice_index], sizeof(char *));
            int *traffic_size = sampleTrafficDiffClass(raw_data_array, labels_array, data_size_array, class_count, traffic_temp, traffic_labels, slice_class_traffic_count[slice_index], TRAFFIC_DATA_TYPE);
            float **traffic = (float **)traffic_temp;
            int *traffic_result = (int *)calloc(traffic_size[0], sizeof(int));
            int box_id;
            int outlier_lst_index = 0;
            int outlier_lst_count = 0;
            int *outlier_lst = (int *)calloc(traffic_size[0], sizeof(int));
            int *points_box = (int *)calloc(traffic_size[0], sizeof(int));
            int num = 0;
            int right = 0;
            int outlier_result = 0;
            int benign_num[MAX_CLUSTER] = {0};
            int boxes_count_old[MAX_CLUSTER] = {0};
            memset(boxes_count, 0, sizeof(boxes_count));
            /********************************************/
            int temp_total_count[MAX_CLUSTER] = {0};
            int temp_benign_count[MAX_CLUSTER] = {0};
            /********************************************/
//            memset(boxes_benign_count, 0, sizeof(boxes_benign_count));
            slice_confusion_mat[slice_index] = (int *)calloc(4, sizeof(int));
            for(int traffic_index = 0; traffic_index < traffic_size[0]; traffic_index++)
            {
                box_id = checkPointBoxFloat(traffic[traffic_index], boxes, iter, traffic_size[1], k);
                points_box[traffic_index] = box_id;
                if(box_id != -1)
                {
                    num++;
                    traffic_result[traffic_index] = boxes_result[box_id];
                    right += statisticConfusionMat((int **)&slice_confusion_mat[slice_index], traffic_labels[traffic_index], "BENIGN", traffic_result[traffic_index]);
                    boxes_count[box_id]++;
                    temp_total_count[box_id]++;
                    if(!strcmp(traffic_labels[traffic_index], "BENIGN"))
                    {
                        benign_num[box_id]++;
                        temp_benign_count[box_id]++;
                    }
                }
                else
                {
                    if(1)
                    {
                        num++;
                        outlier_lst_index++;
                        traffic_result[traffic_index] = outlier_result;
                        right += statisticConfusionMat((int **)&slice_confusion_mat[slice_index], traffic_labels[traffic_index], "BENIGN", traffic_result[traffic_index]);
                    }
//                    else
//                    {
//                        outlier_lst[outlier_lst_index] = traffic_index;
//                        outlier_lst_index++;
//                    }
                }

                if(traffic_index == TRAFFIC_SAMPLE - 1)
                {
                    outlier_lst_count = outlier_lst_index;
                    int bad_box = 0;
                    int empty_box = 0;
                    if(outlier_lst_count > TRAFFIC_SAMPLE / 25)
                    {
                        char moreInfo[100];
                        int traffic_sample_count = traffic_index;
                        int traffic_sample_size[2] = {traffic_sample_count, traffic_size[1]};
                        float **traffic_sample = (float **)calloc(traffic_sample_count, sizeof(float *));
                        for(int i = 0; i < traffic_sample_count; i++)
                        {
                            traffic_sample[i] = (float *)calloc(traffic_sample_size[1], sizeof(float));
                            traffic_sample[i][0] = 12.77 * powf(traffic[i][0], 0.3);
                            traffic_sample[i][1] = 75 * log10(traffic[i][1] + 1.0f);
                            traffic_sample[i][2] = traffic[i][2];
                        }
                        memset(boxes_count, 0, sizeof(boxes_count));
                        start = clock();
                        k = FlowDBScanFloatPro(traffic_sample, traffic_sample_size, points_box, boxes, boxes_count);
                        end = clock();
                        sprintf(moreInfo, "%d_%s_%d_", slice_index + slice_accumu, slices[slice_index], traffic_index);
                        outputDbScanResultFloat(heads, traffic_sample_size, traffic_sample, traffic_labels, points_box, k, timeStr, moreInfo);
                        outputDbScanBoxesFloat(boxes, k, traffic_sample_size[1], timeStr, moreInfo);
                        double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
                        printf("[+] Slice: %d; Traffic: %s; Outlier Count: %d; New Boxes: YES; Time: %.5f secs. \n", slice_index + slice_accumu, slices[slice_index], outlier_lst_count, cpu_time_used);
                        freePointer2Level((void ***)&traffic_sample, traffic_sample_count);
                        for(int i = 0; i < k; i++)
                        {
                            boxes_volume[i] = computeBoxVolFloat(boxes[i], traffic_sample_size[1]);
                            if(META_FEATURE_USE)
                            {
                                boxes_count_old[i] = boxes_count[i];
                                boxes_meta[i][0] = (float)boxes_count[i] / (float)traffic_index;
                                boxes_meta[i][1] = boxes_meta[i][0] * boxes_meta[i][0];
                                boxes_meta[i][2] = log1p((float)boxes_count[i] / ((float)TRAFFIC_SAMPLE / (float)TRAFFIC_CHECK_T));
                                boxes_meta[i][3] = log1p(boxes_volume[i]);
                                boxes_meta[i][4] = 1.0f;
                                boxes_meta_score[i] = computePolynomial(score_weight0, score_weight, boxes_meta[i], 5);
                            }
                            if(SPACE_FEATURE_USE)
                            {
                                boxes_space_score[i] = BoxBadDecisionTreeFloat(boxes[i]) ? 0.3f : -2.5f;
                            }
                            boxes_score[i] = boxes_meta_score[i] + boxes_space_score[i];
                            boxes_result[i] = (boxes_score[i] > 0.0f) ? 1 : 0;
                            if(boxes_result[i] && boxes_count[i] >= 100)
                            {
                                bad_box++;
                            }
                            if(boxes_count[i] < 100)
                            {
                                empty_box++;
                            }
                            boxes[i][0] = powf(boxes[i][0] / 12.77, 1 / 0.3) - 0.001f;
                            boxes[i][1] = powf(boxes[i][1] / 12.77, 1 / 0.3) + 0.001f;
                            boxes[i][2] = powf(10, boxes[i][2] / 75) - 1.0f;
                            boxes[i][3] = powf(10, boxes[i][3] / 75) - 1.0f;
                        }
                        outlier_result = (bad_box > (k - empty_box - bad_box)) ? 1 : 0;
                        Overlap = checkOverlapFloat(boxes, k, traffic_sample_size[1]);
                        if(Overlap)
                        {
                            iter = sortFloat(boxes_volume, k, 1);
                        }
                        else
                        {
                            iter = sortInt(boxes_count, k, 0);
                        }
                        /* --- New --- */
                        memset(temp_benign_count, 0, sizeof(temp_benign_count));
                        memset(temp_total_count, 0, sizeof(temp_total_count));

                        for(int i = 0; i < traffic_sample_count; i++) {
                            int temp_id = checkPointBoxFloat(traffic[i], boxes, iter, traffic_sample_size[1], k);
                            if(temp_id != -1) {
                                temp_total_count[temp_id]++;
                                if(strstr(traffic_labels[i], "BENIGN")) {
                                    temp_benign_count[temp_id]++;
                                }
                            }
                        }
                        for(int i = 0; i < k; i++) {
                            if(temp_total_count[i] > 0) {
                                boxes_meta[i][5] = ((float)temp_total_count[i] - (float)temp_benign_count[i]) / (float)temp_total_count[i];
                            } else {
                                boxes_meta[i][5] = 0.0f;
                            }
//                            printf("%f:%.1f:%d:%d:%d ", boxes_meta_score[i], boxes_space_score[i], boxes_result[i], temp_benign_count[i], temp_total_count[i]);
                        }
//                        printf("\n");
//                        sprintf(moreInfo, "%d_%s_%d_", slice_index + slice_accumu, slices[slice_index], traffic_index);
//                        outputDbScanBoxesFloat(boxes_meta, k, 3, timeStr, moreInfo);
                        /* ------------------------------ */
//                        for(outlier_lst_index = 0; outlier_lst_index < outlier_lst_count; outlier_lst_index++)
//                        {
//                            // Process Outliers
//                            num++;
//                            box_id = checkPointBoxFloat(traffic[outlier_lst[outlier_lst_index]], boxes, iter, traffic_size[1], k);
//                            if(box_id != -1)
//                            {
//                                traffic_result[outlier_lst[outlier_lst_index]] = boxes_result[box_id];
//                            }
//                            else
//                            {
//                                traffic_result[outlier_lst[outlier_lst_index]] = outlier_result;
//                            }
//                            right += statisticConfusionMat((int **)&slice_confusion_mat[slice_index], traffic_labels[outlier_lst[outlier_lst_index]], "BENIGN", traffic_result[outlier_lst[outlier_lst_index]]);
//                        }
                    }
                    else
                    {
                        printf("[+] Slice: %d; Traffic: %s; Outlier Count: %d; New Boxes: NO. \n", slice_index + slice_accumu, slices[slice_index], outlier_lst_count);
                        int del = 0;
                        int *del_idx = (int *)calloc(k, sizeof(int));
                        for(int i = 0; i < k; i++)
                        {
                            if(META_FEATURE_USE)
                            {
                                if(boxes_count[i] < TRAFFIC_SAMPLE / 25)
                                {
                                    boxes_meta[i][4] -= 1.0f / (float)BOX_LIVES;
                                }
                                else
                                {
                                    boxes_meta[i][4] = 1.0f;
                                }
                                boxes_meta[i][0] = (float)boxes_count[i] / (float)traffic_index;
                                boxes_meta[i][1] = boxes_meta[i][0] * boxes_meta[i][0];
                                boxes_meta[i][2] = log1p(fabs((float)boxes_count[i] - (float)boxes_count_old[i]));
                                boxes_meta[i][2] = (boxes_count[i] - boxes_count_old[i] > 0) ? boxes_meta[i][2] : (-boxes_meta[i][2]);
                                boxes_count_old[i] = boxes_count[i];
                                if (temp_total_count[i] > 0)
                                {
                                    boxes_meta[i][5] = ((float)temp_total_count[i] - (float)temp_benign_count[i]) / (float)temp_total_count[i];
                                }
                                else
                                {
                                    boxes_meta[i][5] = 0.0f;
                                }
                                boxes_meta_score[i] = computePolynomial(score_weight0, score_weight, boxes_meta[i], 5);
                                if(boxes_meta[i][4] <= 0.0f)
                                {
                                    del_idx[del] = i;
                                    del++;
                                }
                                boxes_score[i] = boxes_meta_score[i] + boxes_space_score[i];
                                boxes_result[i] = (boxes_score[i] > 0.0f) ? 1 : 0;
//                                printf("%f:%.1f:%d:%d:%d ", boxes_meta_score[i], boxes_space_score[i], boxes_result[i], temp_benign_count[i], temp_total_count[i]);
                                if(boxes_result[i] && boxes_count[i] >= 100)
                                {
                                    bad_box++;
                                }
                                if(boxes_count[i] < 100)
                                {
                                    empty_box++;
                                }
                            }
                        }
                        outlier_result = (bad_box > k - empty_box - bad_box) ? 1 : 0;
//                        printf("\n");
                        if(del > 0)
                        {
                            deleteItems((void *)temp_total_count, sizeof(temp_total_count[0]), k, del_idx, del);
                            deleteItems((void *)temp_benign_count, sizeof(temp_benign_count[0]), k, del_idx, del);
                            deleteItems((void *)boxes_count, sizeof(boxes_count[0]), k, del_idx, del);
                            deleteItems((void *)boxes_volume, sizeof(boxes_volume[0]), k, del_idx, del);
                            deleteItems((void *)boxes_score, sizeof(boxes_volume[0]), k, del_idx, del);
                            deleteItems((void *)boxes_meta, sizeof(boxes_meta[0]), k, del_idx, del);
                            k = deleteItems((void *)boxes, sizeof(boxes[0]), k, del_idx, del);
                        }
                        freePointer1Level((void **)&del_idx);
//                        for(outlier_lst_index = 0; outlier_lst_index < outlier_lst_count; outlier_lst_index++)
//                        {
//                            // Process Outliers
//                            num++;
//                            traffic_result[outlier_lst[outlier_lst_index]] = outlier_result;
//                            right += statisticConfusionMat((int **)&slice_confusion_mat[slice_index], traffic_labels[outlier_lst[outlier_lst_index]], "BENIGN", traffic_result[outlier_lst[outlier_lst_index]]);
//                        }
                    }

                }

                if(traffic_index % TRAFFIC_CHECK_T == 0 && traffic_index && META_FEATURE_USE && traffic_index != TRAFFIC_SAMPLE)
                {
                    int bad_box = 0;
                    int empty_box = 0;
                    for(int i = 0; i < k; i++)
                    {
                        if(META_FEATURE_USE)
                        {
                            boxes_meta[i][0] = (float)boxes_count[i] / (float)traffic_index;
                            boxes_meta[i][1] = boxes_meta[i][0] * boxes_meta[i][0];
                            boxes_meta[i][2] = log1p(fabs((float)boxes_count[i] - (float)boxes_count_old[i]));
                            boxes_meta[i][2] = (boxes_count[i] - boxes_count_old[i] > 0) ? boxes_meta[i][2] : (-boxes_meta[i][2]);
                            boxes_count_old[i] = boxes_count[i];
                            if (temp_total_count[i] > 0)
                            {
                                boxes_meta[i][5] = ((float)temp_total_count[i] - (float)temp_benign_count[i]) / (float)temp_total_count[i];
                            }
                            else
                            {
                                boxes_meta[i][5] = 0.0f;
                            }
                            boxes_meta_score[i] = computePolynomial(score_weight0, score_weight, boxes_meta[i], 5);
                        }
                        boxes_score[i] = boxes_meta_score[i] + boxes_space_score[i];
                        boxes_result[i] = (boxes_score[i] > 0.0f) ? 1 : 0;
//                        printf("%f:%.1f:%d:%d:%d ", boxes_meta_score[i], boxes_space_score[i], boxes_result[i], temp_benign_count[i], temp_total_count[i]);
                        if(boxes_result[i] && boxes_count[i] >= 100)
                        {
                            bad_box++;
                        }
                        if(boxes_count[i] < 100)
                        {
                            empty_box++;
                        }
                    }
                    outlier_result = (bad_box > k - empty_box - bad_box) ? 1 : 0;
//                    printf("\n");
//                    if(slice_index > 0 || traffic_index > TRAFFIC_SAMPLE)
//                    {
//                        char moreInfo[100];
//                        sprintf(moreInfo, "%d_%s_%d_", slice_index + slice_accumu, slices[slice_index], traffic_index);
//                        outputDbScanBoxesFloat(boxes_meta, k, 3, timeStr, moreInfo);
//                    }
                }
            }

//            for(int i = 0; i < 4; i++)
//            {
//                printf("%d ", slice_confusion_mat[slice_index][i]);
//            }
//            printf("%f\n", (float)right / (float)num);
//            for(int i = 0; i < traffic_size[0]; i++)
//            {
//                traffic[i][0] = 12.77 * powf(traffic[i][0], 0.3);
//                traffic[i][1] = 75 * log10(traffic[i][1] + 1.0f);
//                traffic[i][2] = traffic[i][2];
//            }
//            char moreInfo[100];
//            sprintf(moreInfo, "%d_%s_%d_", slice_index + slice_accumu, slices[slice_index], 0);
//            outputDbScanResultFloat(heads, traffic_size, traffic, traffic_labels, points_box, k, timeStr, moreInfo);
            printSliceStatistiacalData(slice_confusion_mat[slice_index]);
            freePointer2Level((void ***)&traffic, slice_traffic_count[slice_index]);
            freePointer2Level((void ***)&traffic_labels, slice_traffic_count[slice_index]);
            freePointer1Level((void **)&traffic_size);
            freePointer1Level((void **)&points_box);
            freePointer1Level((void **)&outlier_lst);
        }
        outputStatisticsToCSV("./data/result/cm/cm.csv", slice_confusion_mat, slice_count);
        printStatistiacalData(slice_confusion_mat, slice_count);
        slice_accumu += slice_count;
        freePointer3Level((void ****)&raw_data_array, class_count, MAX_ROWS);
        freePointer3Level((void ****)&labels_array, class_count, MAX_ROWS);
        freePointer2Level((void ***)&data_size_array, class_count);
        freePointer2Level((void ***)&slice_confusion_mat, slice_count);
        raw_data_array = NULL;
        labels_array = NULL;
    }
    return 0;
}
