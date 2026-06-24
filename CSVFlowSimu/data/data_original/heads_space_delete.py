import csv
import os

def process_csv(input_file, output_file):
    """
    处理CSV文件：
    1. 保留表头行，但清理表头每个字段开头的空格（仅第一个字符是空格时删除）
    2. 数据行保持原样不变
    3. 保留原CSV的列结构和编码
    
    参数：
    input_file: 输入CSV文件路径
    output_file: 输出处理后的CSV文件路径
    """
    # 检查输入文件是否存在
    if not os.path.exists(input_file):
        print(f"错误：输入文件 {input_file} 不存在！")
        return
    
    # 处理CSV文件
    with open(input_file, 'r', encoding='utf-8', newline='') as infile, \
         open(output_file, 'w', encoding='utf-8', newline='') as outfile:
        
        # 创建CSV读取器和写入器
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        
        # 处理表头行（第一行）
        header = next(reader, None)
        if header:  # 确保表头不为空
            processed_header = []
            for col_name in header:
                # 表头字段：第一个字符是空格则删除，否则保持原样
                if col_name and col_name[0] == ' ':
                    processed_col = col_name[1:]
                else:
                    processed_col = col_name
                processed_header.append(processed_col)
            # 写入处理后的表头
            writer.writerow(processed_header)
        
        # 数据行直接原样写入（无需处理）
        for row in reader:
            writer.writerow(row)
    
    print(f"处理完成！结果已保存到：{output_file}")

# 示例用法
if __name__ == "__main__":
    for filename in os.listdir("./"):
        if filename.endswith('.csv'):
            input_file_path = os.path.join("./", filename)
            output_file_path = os.path.join("../data_temp/", filename)
            process_csv(input_file_path, output_file_path)
