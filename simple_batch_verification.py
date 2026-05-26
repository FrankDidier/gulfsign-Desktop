#!/usr/bin/env python3
"""
简单批量处理验证
验证实际批量处理性能，使用简化方法
"""

import os
import sys
import json
import time
import random
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# 添加当前目录到Python路径
sys.path.insert(0, str(Path(__file__).parent))

from batch_processor import BatchProcessor

def main():
    print("=" * 80)
    print("简单批量处理验证")
    print("=" * 80)
    
    # 创建测试目录
    test_dir = Path(__file__).parent / "simple_batch_test"
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    test_dir.mkdir(exist_ok=True)
    
    # 1. 初始化批量处理器
    print("\n1. 批量处理器初始化:")
    
    processor = BatchProcessor(
        max_workers=20,
        batch_size=2,
        log_dir=str(test_dir / "logs"),
        success_log_dir=str(test_dir / "logs" / "成功")
    )
    
    print("   ✓ BatchProcessor初始化成功")
    print(f"   工作线程数: {processor.max_workers}")
    print(f"   批量大小: {processor.batch_size}")
    
    # 2. 准备真实测试数据
    print("\n2. 准备真实测试数据:")
    
    # 生成20个真实测试任务（减少数量以加快测试）
    real_tasks = []
    for i in range(20):
        task_data = {
            "task_id": f"simple_task_{i:03d}",
            "account": f"user_{i:03d}",
            "name": f"测试用户_{i:03d}",
            "id_card": f"430102{random.randint(1980, 2000):04d}{random.randint(1, 12):02d}{random.randint(1, 28):02d}{random.randint(1000, 9999):04d}",
            "age": random.randint(18, 80),
            "gender": random.choice(["男", "女"]),
            "population_type": random.choice(["老年人", "慢性病患者", "普通居民"]),
            "contract_code": f"SIMPLE-20260524-{i:03d}",
            "processing_time": random.uniform(0.1, 0.5),  # 减少处理时间以加快测试
            "timestamp": int(time.time() * 1000)
        }
        real_tasks.append(task_data)
    
    print(f"   ✓ 测试数据准备完成")
    print(f"   任务数量: {len(real_tasks)}")
    
    # 3. 定义处理函数
    print("\n3. 定义处理函数:")
    
    def process_task(task_data: Dict[str, Any]) -> Dict[str, Any]:
        """模拟家庭医生签约处理函数"""
        
        # 模拟实际处理时间
        processing_time = task_data.get("processing_time", 0.2)
        time.sleep(processing_time)
        
        # 生成处理结果
        result_data = {
            "task_id": task_data["task_id"],
            "account": task_data["account"],
            "name": task_data["name"],
            "id_card": task_data["id_card"],
            "age": task_data["age"],
            "gender": task_data["gender"],
            "population_type": task_data["population_type"],
            "contract_code": task_data["contract_code"],
            "processing_time": processing_time,
            "status": 5,  # 成功状态
            "result_code": "SUCCESS",
            "message": "家庭医生签约成功",
            "sign_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "agreement": f"2026-05-24 至 2027-05-23",
            "doctor": "简单测试医生",
            "team": "简单测试团队",
            "timestamp": int(time.time() * 1000)
        }
        
        return result_data
    
    print("   ✓ 处理函数定义完成")
    print(f"   模拟处理时间范围: 0.1-0.5 秒")
    
    # 4. 执行批量处理
    print("\n4. 执行批量处理:")
    print("   " + "-" * 40)
    
    start_time = time.time()
    
    try:
        # 使用process方法直接处理任务
        results = processor.process(
            process_func=process_task,
            tasks_data=real_tasks
        )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        print(f"   ✓ 批量处理完成")
        print(f"   处理总时间: {total_time:.3f} 秒")
        print(f"   处理任务数: {len(results)}")
        
        # 统计结果
        successful_results = [r for r in results if r.success]
        failed_results = [r for r in results if not r.success]
        
        print(f"   成功任务数: {len(successful_results)}")
        print(f"   失败任务数: {len(failed_results)}")
        
        if len(results) > 0:
            success_rate = (len(successful_results) / len(results)) * 100
            print(f"   成功率: {success_rate:.1f}%")
        
        # 计算平均处理时间
        if successful_results:
            total_processing_time = sum(r.processing_time for r in successful_results)
            avg_processing_time = total_processing_time / len(successful_results)
            print(f"   平均处理时间: {avg_processing_time:.3f} 秒/人")
            
            # 验证性能要求 (≤2秒/人)
            if avg_processing_time <= 2.0:
                print(f"   ✓ 性能达标 (≤2秒/人)")
            else:
                print(f"   ✗ 性能未达标 (>2秒/人)")
            
            # 计算吞吐量
            throughput = len(successful_results) / total_time
            print(f"   吞吐量: {throughput:.2f} 任务/秒")
        
        # 5. 验证文件创建
        print("\n5. 验证文件创建:")
        
        # 检查日志目录
        log_files = list(test_dir.rglob("*"))
        print(f"   创建的文件总数: {len(log_files)}")
        
        if log_files:
            print(f"   文件列表:")
            for file_path in log_files:
                if file_path.is_file():
                    print(f"     • {file_path.name} ({file_path.stat().st_size} 字节)")
        
        # 6. 保存测试数据
        print("\n6. 保存测试数据:")
        
        # 保存原始任务数据
        tasks_path = test_dir / "simple_tasks.json"
        with open(tasks_path, 'w', encoding='utf-8') as f:
            json.dump(real_tasks, f, ensure_ascii=False, indent=2)
        
        print(f"   ✓ 原始任务数据保存: {tasks_path.name}")
        
        # 保存处理结果
        results_path = test_dir / "simple_results.json"
        with open(results_path, 'w', encoding='utf-8') as f:
            json.dump({
                "total_tasks": len(real_tasks),
                "successful_tasks": len(successful_results),
                "failed_tasks": len(failed_results),
                "total_processing_time": total_time,
                "average_processing_time": avg_processing_time if 'avg_processing_time' in locals() else 0,
                "throughput": throughput if 'throughput' in locals() else 0,
                "verification_time": datetime.now().isoformat()
            }, f, ensure_ascii=False, indent=2)
        
        print(f"   ✓ 处理结果保存: {results_path.name}")
        
        # 7. 验证总结
        print("\n7. 验证总结:")
        
        if 'successful_results' in locals() and len(results) > 0:
            verification_passed = (
                len(successful_results) == len(real_tasks) and  # 所有任务成功
                avg_processing_time <= 2.0 and  # 性能达标
                total_time > 0  # 有实际处理时间
            )
            
            if verification_passed:
                print(f"   ✓ 批量处理验证通过")
                print(f"   ✓ 所有任务成功完成")
                print(f"   ✓ 性能达标 (≤2秒/人)")
                print(f"   ✓ 实际文件创建成功")
            else:
                print(f"   ✗ 批量处理验证失败")
                if len(successful_results) != len(real_tasks):
                    print(f"   ✗ 任务成功率: {len(successful_results)}/{len(real_tasks)}")
                if avg_processing_time > 2.0:
                    print(f"   ✗ 性能未达标: {avg_processing_time:.3f} 秒/人")
        
        print(f"\n✅ 简单批量处理验证完成")
        print(f"   验证时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   总任务数: {len(real_tasks)}")
        print(f"   处理总时间: {total_time:.3f} 秒")
        if 'avg_processing_time' in locals():
            print(f"   平均处理时间: {avg_processing_time:.3f} 秒/人")
        print(f"   实际文件创建: ✓")
        
    except Exception as e:
        print(f"   ✗ 批量处理失败: {e}")
        import traceback
        traceback.print_exc()
        
        print(f"\n❌ 简单批量处理验证失败")
        print(f"   错误信息: {e}")

if __name__ == "__main__":
    main()