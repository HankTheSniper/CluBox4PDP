import pandas as pd
import os

def process_csv_files(input_folder, output_folder, selected_columns, 
                      sample_size=1000, chunk_size=100000):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    for filename in os.listdir(input_folder):
        if filename.endswith('.csv'):
            input_file_path = os.path.join(input_folder, filename)
            output_file_path = os.path.join(output_folder, filename)
            
            try:
                chunk_iter = pd.read_csv(input_file_path, low_memory=False, chunksize=chunk_size)
                all_chunks = []
                total_rows = 0
                
                # 必须读取的原始列
                required_for_calc = ['Pkt Len Max', 'Pkt Len Min']
                # 确保读取所有需要的列
                temp_read_columns = list(set(selected_columns + required_for_calc))
                
                for chunk in chunk_iter:
                    total_rows += len(chunk)
                    
                    # 检查计算列是否存在
                    if all(col in chunk.columns for col in required_for_calc):
                        # 1. 计算 Range
                        chunk['Pkt Len Range'] = chunk['Pkt Len Max'] - chunk['Pkt Len Min']
                        
                        # 2. 构造最终列顺序逻辑
                        # 获取除了 Label 之外的所有目标列
                        cols_except_label = [col for col in selected_columns if col != 'Label' and col in chunk.columns]
                        
                        # 构造排序后的列列表：[其他列] + [Pkt Len Range] + [Label]
                        final_order = []
                        for col in cols_except_label:
                            if col not in final_order:
                                final_order.append(col)
                        
                        if 'Pkt Len Range' not in final_order:
                            final_order.append('Pkt Len Range')
                        
                        if 'Label' in chunk.columns:
                            final_order.append('Label')
                        
                        # 3. 按照新顺序提取
                        all_chunks.append(chunk[final_order])
                    else:
                        print(f"文件 {filename} 缺失 Pkt Len Max/Min，跳过该块")
                
                if not all_chunks:
                    continue
                
                selected_df = pd.concat(all_chunks, ignore_index=True)
                print(f"{filename} 处理后总行数: {len(selected_df)}")
                
                # 抽样
                sample_count = min(sample_size, len(selected_df))
                sample_df = selected_df.sample(n=sample_count, random_state=42)
                
                # 保存
                sample_df.to_csv(output_file_path, index=False)
                print(f"已保存至: {output_file_path}")
                
                del selected_df, sample_df, all_chunks
                
            except Exception as e:
                print(f"处理 {filename} 出错: {e}")

input_folder = 'data_original'
output_folder = 'data_processed'
selected_columns = ['Pkt Len Max', 'IAT Max', 'Label'] 
sample_size = 20000
chunk_size = 50000

process_csv_files(
    input_folder=input_folder,
    output_folder=output_folder,
    selected_columns=selected_columns,
    sample_size=sample_size,
    chunk_size=chunk_size
)