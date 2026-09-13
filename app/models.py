from datetime import datetime
from sqlalchemy import String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
class User(Base):
    __tablename__='users'; id: Mapped[int]=mapped_column(primary_key=True); username: Mapped[str]=mapped_column(String(80), unique=True); password_hash: Mapped[str]=mapped_column(String(255)); created_at: Mapped[datetime]=mapped_column(DateTime, default=datetime.utcnow)
class Database(Base):
    __tablename__='databases'; id: Mapped[int]=mapped_column(primary_key=True); name: Mapped[str]=mapped_column(String(100),unique=True); description: Mapped[str]=mapped_column(String(255),default='')
class Node(Base):
    __tablename__='nodes'; id: Mapped[int]=mapped_column(primary_key=True); name: Mapped[str]=mapped_column(String(100),unique=True); host: Mapped[str]=mapped_column(String(100)); port: Mapped[int]=mapped_column(Integer); database_name: Mapped[str]=mapped_column(String(100)); trust_level: Mapped[str]=mapped_column(String(30)); allowed_operations: Mapped[str]=mapped_column(Text); allowed_tables: Mapped[str]=mapped_column(Text); status: Mapped[str]=mapped_column(String(30),default='HEALTHY'); workload: Mapped[int]=mapped_column(Integer,default=0); created_at: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow); last_health_check: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
class TableMetadata(Base):
    __tablename__='table_metadata'; id: Mapped[int]=mapped_column(primary_key=True); name: Mapped[str]=mapped_column(String(80),unique=True)
class ColumnMetadata(Base):
    __tablename__='column_metadata'; id: Mapped[int]=mapped_column(primary_key=True); table_name: Mapped[str]=mapped_column(String(80)); name: Mapped[str]=mapped_column(String(80)); classification: Mapped[str]=mapped_column(String(30))
class QueryRequest(Base):
    __tablename__='query_requests'; id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey('users.id')); sql: Mapped[str]=mapped_column(Text); status: Mapped[str]=mapped_column(String(30)); created_at: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
class QueryExecution(Base):
    __tablename__='query_executions'; id: Mapped[int]=mapped_column(primary_key=True); query_id: Mapped[int]=mapped_column(ForeignKey('query_requests.id')); node_name: Mapped[str]=mapped_column(String(100)); result_json: Mapped[str]=mapped_column(Text,default='[]'); execution_time_ms: Mapped[int]=mapped_column(Integer,default=0)
class AuditLog(Base):
    __tablename__='audit_logs'; id: Mapped[int]=mapped_column(primary_key=True); user_id: Mapped[int]=mapped_column(ForeignKey('users.id')); query_id: Mapped[int]=mapped_column(ForeignKey('query_requests.id')); requested_operation: Mapped[str]=mapped_column(String(20)); requested_tables: Mapped[str]=mapped_column(Text); requested_columns: Mapped[str]=mapped_column(Text); selected_node: Mapped[str]=mapped_column(String(100),default=''); node_trust_level: Mapped[str]=mapped_column(String(30),default=''); decision: Mapped[str]=mapped_column(String(20)); reason: Mapped[str]=mapped_column(Text); timestamp: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow); execution_time: Mapped[int]=mapped_column(Integer,default=0); result_status: Mapped[str]=mapped_column(String(30))
class StorageReplica(Base):
    __tablename__='storage_replicas'; id: Mapped[int]=mapped_column(primary_key=True); table_name: Mapped[str]=mapped_column(String(80)); record_id: Mapped[int]=mapped_column(Integer); node_name: Mapped[str]=mapped_column(String(100)); encrypted_payload: Mapped[str]=mapped_column(Text); integrity_hash: Mapped[str]=mapped_column(String(64)); created_at: Mapped[datetime]=mapped_column(DateTime,default=datetime.utcnow)
