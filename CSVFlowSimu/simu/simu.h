#ifndef __SIMU_H
#define __SIMU_H

#define MAX_LINE_LENGTH 1024
#define MAX_FIELDS 50
#define MAX_ROWS 300000
#define DELIMITER ","

#define TRAFFIC_SEQ_SIZE 800
#define TRAFFIC_MAX_SLICE 100
#define TRAFFIC_SAMPLE_RATE 0.35f
#define TRAFFIC_CHECK_T 500
#define TRAFFIC_SAMPLE 5000
#define TRAFFIC_DATA_TYPE TYPE_FLOAT

enum types{
    TYPE_INT,
    TYPE_FLOAT
};

void printInstruction(void);
int getDataFolder(const char *data_folder, char **class_array);
int inputSlices(char **slices, const char *data_folder, int class_count, char **class_array, int *slice_traffic_count, int **slice_class_traffic_count, char **heads, void ***raw_data_array, char ***labels_array, int **data_size_array);
int parse(char *line, char *fields[MAX_FIELDS], char *delimiter);
void freePointer1Level(void **ptr);
void freePointer2Level(void ***ptr, size_t level1_count);
void freePointer3Level(void ****ptr, size_t level2_count, size_t level1_count);
int* readTrafficData(const char *filename, void **data_ptr, char **head_ptr, enum types data_type);
int* readTrafficDataFast(const char *filename, void **data_ptr, char **head_ptr, char **label_ptr, enum types data_type);
int* transposeFloatData(float **data, int *size, float **new_data);
int* sampleTrafficDiffClass(void ***data_ptr_array, char ***label_ptr_array, int **data_size, int class_count, void **sample_ptr, char **samp_label_ptr, int *class_sample, enum types data_type);
int *sampleTrafficFast(void **data_ptr, char** label_ptr, void** sample_ptr, char** samp_label_ptr, int col_count, int row_original ,int row_sample, enum types data_type);

#endif /* __SIMU_H */
