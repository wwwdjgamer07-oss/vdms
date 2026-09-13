import json
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from .database import Base,engine,get_db
from .models import User,Node,Database,QueryRequest,AuditLog,TableMetadata,ColumnMetadata
from .security import hash_password,verify_password,token_for,current_user
from .services import VirtualDatabaseLayer, NaturalLanguageTranslator, NodeHealthMonitor, CLASSIFICATIONS
def seed(db):
    if not db.query(Node).count():
      nodes=[('trusted-node','TRUSTED',['SELECT']),('semi-trusted-node','SEMI_TRUSTED',['SELECT']),('non-trusted-node','NON_TRUSTED',['SELECT'])]
      for name,trust,ops in nodes: db.add(Node(name=name,host=name,port=5432,database_name='tavdb',trust_level=trust,allowed_operations=json.dumps(ops),allowed_tables=json.dumps(list(CLASSIFICATIONS))))
    else:
      for node in db.query(Node).all(): node.allowed_tables=json.dumps(list(CLASSIFICATIONS))
    if not db.query(TableMetadata).count():
      for table,columns in CLASSIFICATIONS.items():
        db.add(TableMetadata(name=table))
        for column,classification in columns.items(): db.add(ColumnMetadata(table_name=table,name=column,classification=classification))
    db.commit()
@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine); db=next(get_db()); seed(db); db.close(); yield
app=FastAPI(title='Trust-Aware Virtual Database',lifespan=lifespan)
app.mount('/dashboard',StaticFiles(directory=str(Path(__file__).resolve().parent.parent / 'dashboard'),html=True),name='dashboard')
@app.get('/', include_in_schema=False)
def home():
    return RedirectResponse(url='/dashboard/')
class Credentials(BaseModel): username:str=Field(min_length=2); password:str=Field(min_length=6)
class NodeIn(BaseModel): name:str; host:str='localhost'; port:int=5432; database_name:str='employees'; trust_level:str; allowed_operations:list[str]=['SELECT']; allowed_tables:list[str]=['employees']
class QueryIn(BaseModel): sql:str; preferred_node:str|None=None
class NaturalQueryIn(BaseModel): prompt:str=Field(min_length=3,max_length=500); preferred_node:str|None=None
class DatabaseIn(BaseModel): name:str; description:str=''
@app.post('/auth/register')
def register(x:Credentials,db:Session=Depends(get_db)):
    if db.query(User).filter_by(username=x.username).first(): raise HTTPException(409,'Username already exists')
    u=User(username=x.username,password_hash=hash_password(x.password));db.add(u);db.commit();return {'id':u.id,'username':u.username}
@app.post('/auth/login')
def login(x:Credentials,db:Session=Depends(get_db)):
    u=db.query(User).filter_by(username=x.username).first()
    if not u or not verify_password(x.password,u.password_hash): raise HTTPException(401,'Invalid credentials')
    return {'access_token':token_for(u),'token_type':'bearer'}
@app.get('/nodes')
def nodes(_:User=Depends(current_user),db:Session=Depends(get_db)): return db.query(Node).all()
@app.get('/nodes/health')
def node_health(_:User=Depends(current_user),db:Session=Depends(get_db)):
    monitor = NodeHealthMonitor()
    report = [monitor.refresh(db, node) for node in db.query(Node).all()]
    db.commit()
    return report
@app.post('/nodes')
def node(x:NodeIn,_:User=Depends(current_user),db:Session=Depends(get_db)):
    n=Node(**x.model_dump(exclude={'allowed_operations','allowed_tables'}),allowed_operations=json.dumps(x.allowed_operations),allowed_tables=json.dumps(x.allowed_tables));db.add(n);db.commit();return n
@app.post('/databases')
def database(x:DatabaseIn,_:User=Depends(current_user),db:Session=Depends(get_db)): d=Database(**x.model_dump());db.add(d);db.commit();return d
@app.get('/databases')
def databases(_:User=Depends(current_user),db:Session=Depends(get_db)): return db.query(Database).all()
@app.post('/queries')
def query(x:QueryIn,u:User=Depends(current_user),db:Session=Depends(get_db)): return VirtualDatabaseLayer().execute(db,u,x.sql,x.preferred_node)
@app.post('/queries/natural')
def natural_query(x:NaturalQueryIn,u:User=Depends(current_user),db:Session=Depends(get_db)):
    try: sql=NaturalLanguageTranslator().translate(x.prompt)
    except ValueError as e: raise HTTPException(422,str(e))
    outcome=VirtualDatabaseLayer().execute(db,u,sql,x.preferred_node)
    outcome['interpreted_sql']=sql
    return outcome
@app.get('/queries/{query_id}')
def get_query(query_id:int,_:User=Depends(current_user),db:Session=Depends(get_db)):
    q=db.get(QueryRequest,query_id)
    if not q: raise HTTPException(404,'Query not found')
    return q
@app.get('/audit/logs')
def logs(_:User=Depends(current_user),db:Session=Depends(get_db)): return db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
@app.get('/health')
def health(): return {'status':'ok','service':'virtual-database-layer'}
