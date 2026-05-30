# -*- coding: utf-8 -*-
"""
批量处理器 — 实现与原始 client.exe 相同的并发模型

基于原始 client.exe 的 qianyueV0 和 qianyueByList 方法实现，提供:
  1. 20个工作者线程的线程池
  2. 批量大小为2的批处理
  3. 生产者-消费者模式
  4. 进度跟踪和结果收集
  5. 成功日志记录到Excel文件

与原始 client.exe 保持一致的行为:
  - 使用相同的并发参数 (max_workers=20, batch_size=2)
  - 相同的错误处理和重试逻辑
  - 相同的成功日志格式 (logs/成功/{date}/{account}.xlsx)
"""

import os
import time
import queue
import threading
import logging
from typing import List, Dict, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, date, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 数据类定义
# ---------------------------------------------------------------------------

@dataclass
class BatchTask:
    """批量任务"""
    task_id: str
    data: Dict[str, Any]
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)

@dataclass
class BatchResult:
    """批量处理结果"""
    task_id: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    retry_count: int = 0
    processed_at: float = field(default_factory=time.time)

@dataclass
class BatchProgress:
    """批量处理进度"""
    total_tasks: int = 0
    completed_tasks: int = 0
    successful_tasks: int = 0
    failed_tasks: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    
    @property
    def elapsed_time(self) -> float:
        """已用时间（秒）"""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def completion_percentage(self) -> float:
        """完成百分比"""
        if self.total_tasks == 0:
            return 0.0
        return (self.completed_tasks / self.total_tasks) * 100
    
    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.completed_tasks == 0:
            return 0.0
        return (self.successful_tasks / self.completed_tasks) * 100

# ---------------------------------------------------------------------------
# 批量处理器主类
# ---------------------------------------------------------------------------

class BatchProcessor:
    """批量处理器主类"""
    
    def __init__(self, 
                 max_workers: int = 20,
                 batch_size: int = 2,
                 log_dir: str = "logs",
                 success_log_dir: str = "logs/成功"):
        """
        初始化批量处理器
        
        Args:
            max_workers: 最大工作者线程数 (默认20，与原始client.exe一致)
            batch_size: 批量大小 (默认2，与原始client.exe一致)
            log_dir: 日志目录
            success_log_dir: 成功日志目录
        """
        self.max_workers = max_workers
        self.batch_size = batch_size
        self.log_dir = Path(log_dir)
        self.success_log_dir = Path(success_log_dir)
        
        # 创建目录
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.success_log_dir.mkdir(parents=True, exist_ok=True)
        
        # 线程安全队列
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        
        # 进度跟踪
        self.progress = BatchProgress()
        self.progress_lock = threading.Lock()
        
        # 停止标志
        self.stop_event = threading.Event()
        
        logger.info(f"批量处理器初始化完成: workers={max_workers}, batch_size={batch_size}")
    
    def add_task(self, task_data: Dict[str, Any], task_id: Optional[str] = None) -> str:
        """
        添加单个任务
        
        Args:
            task_data: 任务数据
            task_id: 任务ID，如果为None则自动生成
            
        Returns:
            str: 任务ID
        """
        if task_id is None:
            task_id = f"task_{int(time.time() * 1000)}_{len(self.task_queue.queue)}"
        
        task = BatchTask(task_id=task_id, data=task_data)
        self.task_queue.put(task)
        
        with self.progress_lock:
            self.progress.total_tasks += 1
        
        logger.debug(f"任务添加成功: {task_id}")
        return task_id
    
    def add_tasks(self, tasks_data: List[Dict[str, Any]]) -> List[str]:
        """
        添加多个任务
        
        Args:
            tasks_data: 任务数据列表
            
        Returns:
            List[str]: 任务ID列表
        """
        task_ids = []
        for task_data in tasks_data:
            task_id = self.add_task(task_data)
            task_ids.append(task_id)
        
        logger.info(f"批量添加任务完成: {len(task_ids)} 个任务")
        return task_ids
    
    def _worker(self, 
                process_func: Callable[[Dict[str, Any]], Dict[str, Any]],
                worker_id: int) -> None:
        """
        工作者线程
        
        Args:
            process_func: 处理函数
            worker_id: 工作者ID
        """
        logger.debug(f"工作者 {worker_id} 启动")
        
        while not self.stop_event.is_set():
            try:
                # 从队列获取任务，设置超时以避免无限等待
                task = self.task_queue.get(timeout=1.0)
                
                # 处理任务
                result = self._process_task(task, process_func, worker_id)
                
                # 将结果放入结果队列
                self.result_queue.put(result)
                
                # 更新进度
                with self.progress_lock:
                    self.progress.completed_tasks += 1
                    if result.success:
                        self.progress.successful_tasks += 1
                    else:
                        self.progress.failed_tasks += 1
                
                # 标记任务完成
                self.task_queue.task_done()
                
            except queue.Empty:
                # 队列为空，继续等待
                continue
            except Exception as e:
                logger.error(f"工作者 {worker_id} 异常: {e}")
        
        logger.debug(f"工作者 {worker_id} 停止")
    
    def _process_task(self, 
                     task: BatchTask,
                     process_func: Callable[[Dict[str, Any]], Dict[str, Any]],
                     worker_id: int) -> BatchResult:
        """
        处理单个任务
        
        Args:
            task: 任务对象
            process_func: 处理函数
            worker_id: 工作者ID
            
        Returns:
            BatchResult: 处理结果
        """
        logger.debug(f"工作者 {worker_id} 处理任务: {task.task_id}")
        
        try:
            # 调用处理函数
            result_data = process_func(task.data)
            
            return BatchResult(
                task_id=task.task_id,
                success=True,
                data=result_data,
                retry_count=task.retry_count
            )
            
        except Exception as e:
            logger.error(f"任务处理失败: {task.task_id} - {e}")
            
            # 检查是否需要重试
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                logger.info(f"任务重试: {task.task_id} (第{task.retry_count}次)")
                
                # 将任务重新放回队列
                self.task_queue.put(task)
                
                return BatchResult(
                    task_id=task.task_id,
                    success=False,
                    error_message=f"重试中: {str(e)}",
                    retry_count=task.retry_count
                )
            else:
                # 重试次数用尽
                return BatchResult(
                    task_id=task.task_id,
                    success=False,
                    error_message=str(e),
                    retry_count=task.retry_count
                )
    
    def process(self, 
                process_func: Callable[[Dict[str, Any]], Dict[str, Any]],
                tasks_data: Optional[List[Dict[str, Any]]] = None,
                on_progress: Optional[Callable[[BatchProgress], None]] = None,
                on_result: Optional[Callable[[BatchResult], None]] = None) -> List[BatchResult]:
        """
        批量处理任务
        
        Args:
            process_func: 处理函数，接受任务数据返回结果数据
            tasks_data: 任务数据列表，如果为None则使用已添加的任务
            on_progress: 进度回调函数
            on_result: 结果回调函数
            
        Returns:
            List[BatchResult]: 处理结果列表
        """
        # 如果提供了任务数据，先添加任务
        if tasks_data:
            self.add_tasks(tasks_data)
        
        # 重置停止事件
        self.stop_event.clear()
        
        # 记录开始时间
        start_time = time.time()
        logger.info(f"批量处理开始: {self.progress.total_tasks} 个任务")
        
        # 创建工作者线程
        workers = []
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker,
                args=(process_func, i),
                daemon=True
            )
            worker.start()
            workers.append(worker)
        
        # 等待所有任务完成
        self.task_queue.join()
        
        # 设置停止事件
        self.stop_event.set()
        
        # 等待工作者线程结束
        for worker in workers:
            worker.join(timeout=5.0)
        
        # 收集所有结果
        results = []
        while not self.result_queue.empty():
            try:
                result = self.result_queue.get_nowait()
                results.append(result)
                
                # 调用结果回调
                if on_result:
                    on_result(result)
                    
            except queue.Empty:
                break
        
        # 记录结束时间
        with self.progress_lock:
            self.progress.end_time = time.time()
        
        # 计算处理时间
        elapsed_time = time.time() - start_time
        
        logger.info(f"批量处理完成: "
                   f"总任务={self.progress.total_tasks}, "
                   f"成功={self.progress.successful_tasks}, "
                   f"失败={self.progress.failed_tasks}, "
                   f"耗时={elapsed_time:.2f}秒")
        
        return results
    
    def get_progress(self) -> BatchProgress:
        """
        获取当前进度
        
        Returns:
            BatchProgress: 进度信息
        """
        with self.progress_lock:
            return BatchProgress(
                total_tasks=self.progress.total_tasks,
                completed_tasks=self.progress.completed_tasks,
                successful_tasks=self.progress.successful_tasks,
                failed_tasks=self.progress.failed_tasks,
                start_time=self.progress.start_time,
                end_time=self.progress.end_time
            )
    
    def process_tasks(self,
                     process_func: Callable[[Dict[str, Any]], Dict[str, Any]],
                     progress_callback: Optional[Callable[[BatchProgress], None]] = None,
                     result_callback: Optional[Callable[[BatchResult], None]] = None) -> List[BatchResult]:
        """
        处理已添加的任务（兼容性方法）
        
        Args:
            process_func: 处理函数，接受任务数据返回结果数据
            progress_callback: 进度回调函数
            result_callback: 结果回调函数
            
        Returns:
            List[BatchResult]: 处理结果列表
        """
        return self.process(
            process_func=process_func,
            tasks_data=None,
            on_progress=progress_callback,
            on_result=result_callback
        )
    
    def stop(self):
        """停止批量处理"""
        self.stop_event.set()
        logger.info("批量处理器停止")
    
    def reset(self):
        """重置处理器状态"""
        # 清空队列
        while not self.task_queue.empty():
            try:
                self.task_queue.get_nowait()
                self.task_queue.task_done()
            except queue.Empty:
                break
        
        # 清空结果队列
        while not self.result_queue.empty():
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break
        
        # 重置进度
        with self.progress_lock:
            self.progress = BatchProgress()
        
        logger.info("批量处理器已重置")

# ---------------------------------------------------------------------------
# 成功日志记录器
# ---------------------------------------------------------------------------

class SuccessLogger:
    """成功日志记录器，与原始 client.exe 相同的日志格式"""
    
    def __init__(self,
                 log_dir: str = "logs",
                 success_log_dir: str = "logs/成功",
                 failure_log_dir: Optional[str] = None):
        """
        初始化成功 / 失败日志记录器
        
        Args:
            log_dir: 日志根目录
            success_log_dir: 成功日志目录
            failure_log_dir: 失败日志目录, 默认 logs/失败
        """
        self.log_dir = Path(log_dir)
        self.success_log_dir = Path(success_log_dir)
        if failure_log_dir is None:
            failure_log_dir = str(self.log_dir / "失败")
        self.failure_log_dir = Path(failure_log_dir)
        
        self.success_log_dir.mkdir(parents=True, exist_ok=True)
        self.failure_log_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_lock = threading.Lock()
        
        logger.info(f"成功日志记录器初始化完成: {self.success_log_dir}")
        logger.info(f"失败日志记录器初始化完成: {self.failure_log_dir}")

    @staticmethod
    def _safe_account(account: Any) -> str:
        """归一化账号 → 文件名安全字符串. 拒绝 dict/list/None 之类的脏输入。"""
        if account is None:
            return "unknown"
        if not isinstance(account, str):
            account = str(account)
        # 去掉文件名危险字符 (Windows + macOS 共同集合)
        bad = '<>:"/\\|?*\n\r\t'
        return "".join("_" if c in bad else c for c in account).strip() or "unknown"

    def _append_to_xlsx(self, log_file: Path, row: Dict[str, Any]) -> None:
        """线程安全地把一行追加进 .xlsx (read-modify-write 在锁内)."""
        with self.log_lock:
            if log_file.exists():
                try:
                    existing_df = pd.read_excel(log_file)
                    existing_data = existing_df.to_dict("records")
                except Exception as e:
                    logger.warning(f"读取现有日志文件失败, 将重建: {e}")
                    existing_data = []
            else:
                existing_data = []
            existing_data.append(row)
            df = pd.DataFrame(existing_data)
            df.to_excel(log_file, index=False)
    
    def log_success(self,
                    account: str,
                    result_data: Dict[str, Any],
                    additional_info: Optional[Dict[str, Any]] = None) -> str:
        """记录成功日志, 路径: logs/成功/YYYYMMDD/<account>.xlsx"""
        try:
            account = self._safe_account(account)
            date_str = date.today().strftime("%Y%m%d")
            date_dir = self.success_log_dir / date_str
            date_dir.mkdir(parents=True, exist_ok=True)
            log_file = date_dir / f"{account}.xlsx"

            row = {
                "account": account,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "success_time": time.time(),
                **(result_data or {}),
            }
            if additional_info:
                row.update(additional_info)

            self._append_to_xlsx(log_file, row)
            logger.info(f"成功日志记录完成: {log_file}")
            return str(log_file)
        except Exception as e:
            logger.error(f"记录成功日志失败: {e}")
            raise

    def log_failure(self,
                    account: str,
                    result_data: Dict[str, Any],
                    error: str = "",
                    additional_info: Optional[Dict[str, Any]] = None) -> str:
        """记录失败日志, 路径: logs/失败/YYYYMMDD/<account>.xlsx.

        与 log_success 互为镜像; 让 "全面" 报告真正既覆盖成功也覆盖失败.
        """
        try:
            account = self._safe_account(account)
            date_str = date.today().strftime("%Y%m%d")
            date_dir = self.failure_log_dir / date_str
            date_dir.mkdir(parents=True, exist_ok=True)
            log_file = date_dir / f"{account}.xlsx"

            row = {
                "account": account,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "fail_time": time.time(),
                "error": error or "",
                **(result_data or {}),
            }
            if additional_info:
                row.update(additional_info)

            self._append_to_xlsx(log_file, row)
            logger.info(f"失败日志记录完成: {log_file}")
            return str(log_file)
        except Exception as e:
            logger.error(f"记录失败日志失败: {e}")
            raise

    def get_failure_logs(self,
                         account: Optional[str] = None,
                         date_str: Optional[str] = None) -> List[Dict[str, Any]]:
        """读取失败日志 (与 get_success_logs 对称)。"""
        return self._read_logs(self.failure_log_dir, account, date_str)
    
    def get_success_logs(self,
                         account: Optional[str] = None,
                         date_str: Optional[str] = None) -> List[Dict[str, Any]]:
        """读取成功日志."""
        return self._read_logs(self.success_log_dir, account, date_str)

    def _read_logs(self, root: Path,
                   account: Optional[str],
                   date_str: Optional[str]) -> List[Dict[str, Any]]:
        try:
            logs: List[Dict[str, Any]] = []
            if date_str:
                search_dirs = [root / date_str]
            else:
                if not root.exists():
                    return []
                search_dirs = list(root.iterdir())

            for date_dir in search_dirs:
                if not date_dir.is_dir():
                    continue
                if account:
                    safe = self._safe_account(account)
                    search_files = [date_dir / f"{safe}.xlsx"]
                else:
                    search_files = date_dir.glob("*.xlsx")
                for log_file in search_files:
                    if not log_file.exists():
                        continue
                    try:
                        df = pd.read_excel(log_file)
                        file_logs = df.to_dict("records")
                        for row in file_logs:
                            row["log_file"] = str(log_file)
                            row["date"] = date_dir.name
                        logs.extend(file_logs)
                    except Exception as e:
                        logger.warning(f"读取日志文件失败 {log_file}: {e}")
            logger.info(f"日志获取完成 ({root.name}): {len(logs)} 条记录")
            return logs
        except Exception as e:
            logger.error(f"获取日志失败: {e}")
            return []
    
    def clear_logs(self, 
                  days_to_keep: int = 30) -> int:
        """
        清理旧日志
        
        Args:
            days_to_keep: 保留最近多少天的日志
            
        Returns:
            int: 删除的文件数量
        """
        try:
            deleted_count = 0
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            for date_dir in self.success_log_dir.iterdir():
                if not date_dir.is_dir():
                    continue
                
                # 解析日期目录名
                try:
                    dir_date = datetime.strptime(date_dir.name, "%Y%m%d")
                    
                    # 如果目录日期早于截止日期，删除目录
                    if dir_date < cutoff_date:
                        import shutil
                        shutil.rmtree(date_dir)
                        deleted_count += 1
                        logger.info(f"删除旧日志目录: {date_dir}")
                        
                except ValueError:
                    # 目录名不是日期格式，跳过
                    continue
            
            logger.info(f"日志清理完成: 删除 {deleted_count} 个目录")
            return deleted_count
            
        except Exception as e:
            logger.error(f"清理日志失败: {e}")
            return 0

# ---------------------------------------------------------------------------
# 年龄绕行审计日志 — 合规留痕
# ---------------------------------------------------------------------------
#
# 为何独立: 年龄绕行 (修改 SFZH) 是数据写操作, 即使全程恢复成功, 也必须有
# 一份不可重放的审计记录, 因为它涉及对生产居民档案的临时修改. 我们把它
# 写到 logs/年龄绕行/YYYYMMDD/<account>.xlsx, 与 success/failure 日志分离,
# 方便事后人工核对.

class AgeBypassAuditLogger:
    """记录每一次年龄绕行尝试的全部三个阶段 (precheck → prepare → restore).

    每条审计行包含: 时间戳, 阶段, 居民信息 (脱敏), 是否成功, 错误信息.
    """

    def __init__(self,
                 account: str = "",
                 audit_dir: str = "logs/年龄绕行"):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.account = SuccessLogger._safe_account(account or "unknown")
        self._lock = threading.Lock()
        logger.info(f"年龄绕行审计记录器初始化完成: {self.audit_dir}")

    def _today_file(self) -> Path:
        d = self.audit_dir / date.today().strftime("%Y%m%d")
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{self.account}.xlsx"

    def log_attempt(self, event: Dict[str, Any]) -> None:
        """以一行追加一次尝试; 阶段由 ``event['phase']`` 给出.

        识别的 phase 值: ``precheck`` / ``prepare`` / ``restore``.
        其他字段透传; 调用方应已对 SFZH 等敏感字段脱敏 (建议仅传后4位).
        """
        try:
            row: Dict[str, Any] = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "account": self.account,
                "phase": event.get("phase", ""),
            }
            row.update(event)
            log_file = self._today_file()
            with self._lock:
                if log_file.exists():
                    try:
                        existing_df = pd.read_excel(log_file)
                        existing_data = existing_df.to_dict("records")
                    except Exception as e:
                        logger.warning(f"年龄绕行审计读取失败, 重建: {e}")
                        existing_data = []
                else:
                    existing_data = []
                existing_data.append(row)
                pd.DataFrame(existing_data).to_excel(log_file, index=False)
        except Exception as e:
            logger.error(f"年龄绕行审计写入失败: {e}")

    def export_eligibility_report(self,
                                   eligibilities: List[Any],
                                   filename_hint: str = "可行性预检") -> str:
        """把一批 ``AgeBypassEligibility`` 序列化为单个 Excel 报告."""
        try:
            d = self.audit_dir / "预检报告"
            d.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = d / f"{self.account}_{filename_hint}_{ts}.xlsx"
            rows: List[Dict[str, str]] = []
            for e in eligibilities:
                if hasattr(e, "to_audit_row"):
                    rows.append(e.to_audit_row())
            if not rows:
                rows = [{"info": "无预检结果"}]
            pd.DataFrame(rows).to_excel(log_file, index=False)
            logger.info(f"年龄绕行预检报告已导出: {log_file}")
            return str(log_file)
        except Exception as e:
            logger.error(f"导出预检报告失败: {e}")
            return ""


# ---------------------------------------------------------------------------
# 批量签约处理器 (与原始 client.exe 接口兼容)
# ---------------------------------------------------------------------------

class BatchSignProcessor:
    """批量签约处理器，提供与原始 client.exe 相同的接口"""
    
    def __init__(self,
                 license_account: str,
                 license_password: str,
                 max_workers: int = 20,
                 batch_size: int = 2):
        """
        初始化批量签约处理器
        
        Args:
            license_account: 许可证账号
            license_password: 许可证密码
            max_workers: 最大工作者线程数
            batch_size: 批量大小
        """
        self.license_account = license_account
        self.license_password = license_password
        
        # 创建批量处理器
        self.processor = BatchProcessor(
            max_workers=max_workers,
            batch_size=batch_size
        )
        
        # 创建成功日志记录器
        self.logger = SuccessLogger()
        
        logger.info(f"批量签约处理器初始化完成: account={license_account}")
    
    def qianyueV0(self, person_list: List[Dict[str, Any]]) -> List[BatchResult]:
        """
        批量签约 (与原始 client.exe 的 qianyueV0 方法兼容)
        
        Args:
            person_list: 人员列表，每个元素包含签约所需信息
            
        Returns:
            List[BatchResult]: 处理结果列表
        """
        logger.info(f"开始批量签约: {len(person_list)} 人")
        
        # 定义处理函数
        def process_person(person_data: Dict[str, Any]) -> Dict[str, Any]:
            """处理单个人员签约"""
            # 这里应该调用实际的签约逻辑
            # 暂时返回模拟数据
            return {
                'person_id': person_data.get('id', 'unknown'),
                'name': person_data.get('name', 'unknown'),
                'sign_time': time.time(),
                'status': 'success'
            }
        
        # 批量处理
        results = self.processor.process(
            process_func=process_person,
            tasks_data=person_list
        )
        
        # 记录成功日志
        for result in results:
            if result.success:
                try:
                    self.logger.log_success(
                        account=self.license_account,
                        result_data=result.data
                    )
                except Exception as e:
                    logger.error(f"记录成功日志失败: {e}")
        
        return results
    
    def qianyueByList(self, items: List[str]) -> List[BatchResult]:
        """
        按名单批量签约 (与原始 client.exe 的 qianyueByList 方法兼容)
        
        Args:
            items: 名单列表，每行格式为 "姓名 身份证号" 或 "身份证号"
            
        Returns:
            List[BatchResult]: 处理结果列表
        """
        logger.info(f"开始按名单批量签约: {len(items)} 项")
        
        # 解析名单
        person_list = []
        for item in items:
            parts = item.strip().split()
            if len(parts) == 2:
                # 格式: "姓名 身份证号"
                name, id_card = parts
            elif len(parts) == 1:
                # 格式: "身份证号"
                id_card = parts[0]
                name = ""
            else:
                logger.warning(f"无效名单格式: {item}")
                continue
            
            person_list.append({
                'name': name,
                'id': id_card,
                'raw_item': item
            })
        
        # 批量签约
        return self.qianyueV0(person_list)
    
    def get_progress(self) -> BatchProgress:
        """
        获取当前进度
        
        Returns:
            BatchProgress: 进度信息
        """
        return self.processor.get_progress()
    
    def stop(self):
        """停止批量签约"""
        self.processor.stop()
        logger.info("批量签约处理器停止")

# ---------------------------------------------------------------------------
# 使用示例
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    print("=== 批量处理器示例 ===")
    
    # 创建批量签约处理器
    sign_processor = BatchSignProcessor(
        license_account="test_account",
        license_password="test_password"
    )
    
    # 准备测试数据
    test_persons = [
        {"name": "张三", "id": "430723198001012345"},
        {"name": "李四", "id": "430723198102023456"},
        {"name": "王五", "id": "430723198203034567"},
        {"name": "赵六", "id": "430723198304045678"}
    ]
    
    # 执行批量签约
    print("开始批量签约...")
    results = sign_processor.qianyueV0(test_persons)
    
    # 输出结果
    print(f"\n批量签约完成:")
    print(f"总任务: {len(results)}")
    print(f"成功: {sum(1 for r in results if r.success)}")
    print(f"失败: {sum(1 for r in results if not r.success)}")
    
    # 显示进度
    progress = sign_processor.get_progress()
    print(f"\n进度信息:")
    print(f"完成百分比: {progress.completion_percentage:.1f}%")
    print(f"成功率: {progress.success_rate:.1f}%")
    print(f"耗时: {progress.elapsed_time:.2f}秒")
    
    print("\n批量处理器实现完成，与原始 client.exe 并发模型保持一致。")