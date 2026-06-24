#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <time.h>
#include "./simu.h"

#define LARGE_RAND() (((long)rand() << 15) | (long)rand())

void printInstruction()
{
    printf("____________________________________________________________________________________\n");
    printf("               ______ ___ _    __   ________    _______       __\n");
    printf("              / ____/ ___| |  / /  / ____/ /   / __  / |     / /\n");
    printf("             / /    \\__ \\| | / /  / /_  / /   / / / /| | /| / / \n");
    printf("            / /___ ___/ /| |/ /  / __/ / /___/ /_/ / | |/ |/ /  \n");
    printf("            \\____//____/ |___/  /_/   /_____/\\____/  |__/|__/   \n");
    printf("                                                                    \n");
    printf("                  _____ ____ __  __ _    _ _     ___  __________  ____        \n");
    printf("                 / ___//  _//  |/  / /  / / /   /   |/_  __/ __ \\/ __ \\       \n");
    printf("                 \\__ \\ / / / /|_/ / /  / / /   / /| | / / / / / / /_/ /       \n");
    printf("                ___/ // / / /  / / /__/ / /___/ ___ |/ / / /_/ / _  _/        \n");
    printf("               /____/___//_/  /_/\\_____/_____/_/  |_|_/  \\____/_/ |_|         \n");
    printf("____________________________________________________________________________________\n");
    printf("***********************************************************************************\n");
    printf("*  [ INSTRUCTIONS ]                                                               *\n");
    printf("*  1. Traffic's Type              : Different letters (e.g. a, b, c)              *\n");
    printf("*  2. Traffic's Quantity          : Number of letters (e.g. aa, bbbb, ccc)        *\n");
    printf("*  3. Traffic in One Time Slice   : A continuous string of letters (e.g. aabbbb)  *\n");
    printf("*  4. Traffic in Many Time Slices : Use '/' to divide different time slices       *\n");
    printf("*                                                                                 *\n");
    printf("*  e.g.                                                                           *\n");
    printf("*  >> aaaaa/aaab/aaabbb/abbbbbb/bbbbbbbbbb/bbbbbbbbbb/aaab/aaaaa                  *\n");
    printf("*                                                                by. H4nkDASn1p3r *\n");
    printf("***********************************************************************************\n");
    printf("                        >> Press Enter to Start Using <<\n");
    getchar();
}

int getDataFolder(const char *data_folder, char **class_array)
{
    WIN32_FIND_DATA find_data;
    const char search_pattern[10] = "*.csv";
    char data_path[80];
    sprintf(data_path, "%s%s", data_folder, search_pattern);
    int class_index = 0;
    HANDLE hfind = FindFirstFile(data_path, &find_data);
    if (hfind == INVALID_HANDLE_VALUE)
    {
        printf("[-] No data in %s\n", data_path);
        return -1;
    }
    do{
        if(!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            class_array[class_index] = (char *)calloc(20, sizeof(char));
            strcpy(class_array[class_index], find_data.cFileName);
            printf("%c: %s\n", 'a' + class_index, find_data.cFileName);
            class_index++;
        }
        if(class_index > 26)
        {
            printf("[-] To many classes... Do you really need so many...? \n");
            return -1;
        }
    }while(FindNextFile(hfind, &find_data) != 0);

    FindClose(hfind);

    return class_index;
}

int parse(char *line, char *fields[MAX_FIELDS], char *delimiter)
{
    int fields_num = 0;
    char *token = strtok(line, delimiter);
    while(token != NULL && fields_num < MAX_FIELDS)
    {
        fields[fields_num] = strdup(token);
        fields_num++;
        token = strtok(NULL, delimiter);
    }
    return fields_num;
}

void freePointer1Level(void **ptr)
{
    if(ptr != NULL && *ptr != NULL)
    {
        free(*ptr);
        *ptr = NULL;
    }
}

void freePointer2Level(void ***ptr, size_t level1_count)
{
    if(ptr != NULL && *ptr != NULL)
    {
        void **level1_ptr = *ptr;
        for(size_t i = 0; i < level1_count; i++)
        {
            freePointer1Level(&level1_ptr[i]);
        }
        free(*ptr);
        *ptr = NULL;
    }
}

void freePointer3Level(void ****ptr, size_t level2_count, size_t level1_count)
{
    if(ptr != NULL && *ptr != NULL)
    {
        void ***level2_ptr = *ptr;
        for (size_t i = 0; i < level2_count; i++)
        {
            freePointer2Level(&level2_ptr[i], level1_count);
        }
        free(*ptr);
        *ptr = NULL;
    }
}

int* readTrafficDataFast(const char *filename, void **data_ptr, char **head_ptr, char **label_ptr, enum types data_type)
{
    FILE *file = fopen(filename, "r");
    char line[MAX_LINE_LENGTH];
    char *fields[MAX_FIELDS];
    char *heads[MAX_FIELDS];
    char have_label = 0;
    int fields_num;
    int row = 0, col;

    if (!file) {
        printf("[-] Can't open the data file\n");
        return NULL;
    }

    fgets(line, MAX_LINE_LENGTH, file);
    line[strcspn(line, "\n")] = '\0';
    fields_num = parse(line, heads, DELIMITER);

    int flows_num = 0;
    while(fgets(line, MAX_LINE_LENGTH, file) != NULL)
    {
        line[strcspn(line, "\n")] = '\0';
        fields_num = parse(line, fields, DELIMITER);
        if(data_type == TYPE_FLOAT)
        {
            data_ptr[flows_num] = malloc((fields_num) * sizeof(float));
        }
        else if(data_type == TYPE_INT)
        {
            data_ptr[flows_num] = malloc((fields_num) * sizeof(int));
        }
        label_ptr[flows_num] = malloc(15 * sizeof(char));
        for(int j = 0; j < fields_num; j++)
        {
            if(!strcmp(heads[j], "Label"))
            {
                strcpy(label_ptr[flows_num], fields[j]);
            }
            else if(data_type == TYPE_FLOAT)
            {
                *((float*)data_ptr[flows_num] + j) = (float)atof(fields[j]);
            }
            else if(data_type == TYPE_INT)
            {
                *((int*)data_ptr[flows_num] + j) = (int)atoi(fields[j]);
            }
        }
        for (size_t i = 0; i < fields_num; i++)
        {
            freePointer1Level((void **)&fields[i]);
        }
        flows_num++;
    }
    fclose(file);
    for(int i = 0; i < fields_num; i++)
    {
        head_ptr[i] = (char *)calloc(50, sizeof(char));
        strcpy(head_ptr[i], heads[i]);
    }
    int* data_size = (int*)malloc(2 * sizeof(int));
    data_size[0] = flows_num;
    data_size[1] = fields_num - 1;

    return data_size;
}

int *sampleTrafficFast(void **data_ptr, char** label_ptr, void** sample_ptr, char** samp_label_ptr, int col_count, int row_original ,int row_sample, enum types data_type)
{
    srand(time(NULL));
    int row_index = 0;
    int col_index = 0;
    for(row_index = 0; row_index < row_sample; row_index++)
    {
        if(data_type == TYPE_FLOAT)
        {
            sample_ptr[row_index] = (float *)calloc(col_count, sizeof(float));
        }
        else if(data_type == TYPE_INT)
        {
            sample_ptr[row_index] = (int *)calloc(col_count, sizeof(int));
        }
        samp_label_ptr[row_index] = (char *)calloc(15, sizeof(char));
        int random_num = LARGE_RAND() % row_original;
        for(col_index = 0; col_index < col_count; col_index++)
        {
            if(data_type == TYPE_FLOAT)
            {
                ((float**)sample_ptr)[row_index][col_index] = ((float **)data_ptr)[random_num][col_index];
            }
            else if(data_type == TYPE_INT)
            {
                ((int**)sample_ptr)[row_index][col_index] = ((int **)data_ptr)[random_num][col_index];
            }
        }
        strcpy(samp_label_ptr[row_index], label_ptr[random_num]);
    }
    int* samp_data_size = (int*)malloc(2 * sizeof(int));
    samp_data_size[0] = row_sample;
    samp_data_size[1] = col_count;
    return samp_data_size;
}

int* sampleTrafficDiffClass(void ***data_ptr_array, char ***label_ptr_array, int **data_size, int class_count, void **sample_ptr, char **samp_label_ptr, int *class_sample, enum types data_type)
{
    int class_index = 0;
    int col_count = 0;
    int row_sample = 0;
    int smp[15] = {0};

    for(class_index = 0; class_index < class_count; class_index++)
    {
        row_sample += class_sample[class_index];
        if(data_size[class_index] != NULL)
        {
            col_count = data_size[class_index][1];;
        }
    }
    for(int row = 0; row < row_sample; row++)
    {
        int random_num = LARGE_RAND() % row_sample;
        int row_sample_posblty = 0;
        for(class_index = 0; class_index < class_count; class_index++)
        {
            row_sample_posblty += class_sample[class_index];
            if(random_num < row_sample_posblty)
            {
                row_sample_posblty = 0;
                break;
            }
        }
        if(data_type == TYPE_FLOAT)
        {
            sample_ptr[row] = (float *)calloc(col_count, sizeof(float));
        }
        else if(data_type == TYPE_INT)
        {
            sample_ptr[row] = (int *)calloc(col_count, sizeof(int));
        }
        samp_label_ptr[row] = (char *)calloc(15, sizeof(char));
        random_num = LARGE_RAND() % data_size[class_index][0];
        for(int col = 0; col < col_count; col++)
        {
            if(data_type == TYPE_FLOAT)
            {
                ((float**)sample_ptr)[row][col] = ((float **)(data_ptr_array[class_index]))[random_num][col];
            }
            else if(data_type == TYPE_INT)
            {
                ((int**)sample_ptr)[row][col] = ((int **)(data_ptr_array[class_index]))[random_num][col];
            }
        }
        strcpy(samp_label_ptr[row], label_ptr_array[class_index][random_num]);
    }
    int* samp_data_size = (int*)malloc(2 * sizeof(int));
    samp_data_size[0] = row_sample;
    samp_data_size[1] = col_count;
    return samp_data_size;
}

int inputSlices(char **slices, const char *data_folder, int class_count, char **class_array, int *slice_traffic_count, int **slice_class_traffic_count, char **heads, void ***raw_data_array, char ***labels_array, int **data_size_array)
{
    char data_path[512];
    char input[TRAFFIC_SEQ_SIZE];
    char input_temp[TRAFFIC_SEQ_SIZE];
    int slice_count = -1;
    int slice_index;
    int class_index;
    printf("[*] Please input your traffic string.\n");
    printf(">> ");
    scanf("%s", input);
    strcpy(input_temp, input);
    slice_count = parse(input_temp, slices, "/");

    for(slice_index = 0; slice_index < slice_count; slice_index++)
    {
        slice_traffic_count[slice_index] = 0;
        slice_class_traffic_count[slice_index] = calloc(class_count, sizeof(int));
    }
    slice_index = 0;
    char last_slash = 0;

    for(int str_i = 0; str_i < strlen(input); str_i++)
    {
        if(input[str_i] >= 'a' && input[str_i] < 'a' + class_count)
        {
            last_slash = 0;
            class_index = (int)(input[str_i] - 'a');
            if(raw_data_array[class_index] == NULL)
            {
                sprintf(data_path, "%s%s", data_folder, class_array[class_index]);
                raw_data_array[class_index] = (void **)calloc(MAX_ROWS, sizeof(void *));
                labels_array[class_index] = (char **)calloc(MAX_ROWS, sizeof(char *));
                data_size_array[class_index] = readTrafficDataFast(data_path, raw_data_array[class_index], heads, labels_array[class_index], TRAFFIC_DATA_TYPE);
            }
            if (data_size_array[class_index] != NULL)
            {
                slice_class_traffic_count[slice_index][class_index] += (int)(data_size_array[class_index][0] * TRAFFIC_SAMPLE_RATE);
                slice_traffic_count[slice_index] += (int)(data_size_array[class_index][0] * TRAFFIC_SAMPLE_RATE);
            }
        }
        else if(input[str_i] == '/')
        {
            if(!last_slash)
            {
                last_slash = 1;
                slice_index++;
            }
        }
        else
        {
            printf("[-] Wrong typing...\n");
            return -1;
        }
    }

    return slice_count;
}
