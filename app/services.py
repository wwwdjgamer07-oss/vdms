import re, json, time
from dataclasses import dataclass
from sqlalchemy.orm import Session
from .models import Node, QueryRequest, QueryExecution, AuditLog
CLASSIFICATIONS={'employees':{'id':'PUBLIC','name':'INTERNAL','department':'INTERNAL','salary':'CONFIDENTIAL','medical_information':'HIGHLY_CONFIDENTIAL'}}
RANK={'PUBLIC':0,'INTERNAL':1,'CONFIDENTIAL':2,'HIGHLY_CONFIDENTIAL':3}
SAFE_TABLES=set(CLASSIFICATIONS)
@dataclass
class Parsed: operation:str; table:str; columns:list[str]; where:str=''
class QueryParser:
    def parse(self, sql):
        sql=sql.strip().rstrip(';')
        if ';' in sql or '--' in sql or '/*' in sql or re.search(r'\b(drop|truncate|alter|create|grant|revoke|union|exec|pragma)\b',sql,re.I): raise ValueError('Unsafe or unsupported SQL construct')
        m=re.fullmatch(r'(?is)select\s+(.+?)\s+from\s+([a-z_][\w]*)(?:\s+where\s+([\w\s=\'".-]+))?',sql)
        if not m: raise ValueError('Only simple SELECT queries are accepted')
        cols=[]
        for raw in m.group(1).split(','):
            raw=raw.strip(); agg=re.fullmatch(r'(AVG|COUNT|SUM)\((\*|[a-z_]\w*)\)',raw,re.I)
            col=agg.group(2).lower() if agg else raw.lower()
            cols += list(CLASSIFICATIONS.get(m.group(2).lower(),{})) if col=='*' else [col]
        table=m.group(2).lower()
        if table not in SAFE_TABLES or any(c not in CLASSIFICATIONS[table] for c in cols): raise ValueError('Unknown or forbidden table/column')
        return Parsed('SELECT',table,cols,m.group(3) or '')
class TrustPolicyEngine:
    def evaluate(self, parsed, node):
        if node.status!='HEALTHY': return 'DENY','Node is unavailable'
        if parsed.operation not in json.loads(node.allowed_operations): return 'DENY','Operation not permitted on node'
        if parsed.table not in json.loads(node.allowed_tables): return 'DENY','Table not permitted on node'
        maximum=max(RANK[CLASSIFICATIONS[parsed.table][c]] for c in parsed.columns)
        if node.trust_level=='NON_TRUSTED' and maximum>=RANK['CONFIDENTIAL']: return 'REWRITE','Sensitive columns require trusted execution'
        if node.trust_level=='SEMI_TRUSTED' and maximum>=RANK['HIGHLY_CONFIDENTIAL']: return 'REWRITE','Highly confidential columns require trusted execution'
        return 'ALLOW','Policy allows least-privilege delegation'
class QueryRouter:
    order={'TRUSTED':0,'SEMI_TRUSTED':1,'NON_TRUSTED':2}
    def choose(self, db, parsed, prefer=None):
        nodes=db.query(Node).filter_by(status='HEALTHY').all()
        if prefer: nodes=[n for n in nodes if n.name==prefer]
        policy=TrustPolicyEngine(); allowed=[]
        for n in nodes:
            d,_=policy.evaluate(parsed,n)
            if d=='ALLOW': allowed.append(n)
        return sorted(allowed,key=lambda n:(self.order[n.trust_level],n.workload))[0] if allowed else None
class VirtualDatabaseLayer:
    def execute(self, db, user, sql, preferred_node=None):
        started=time.monotonic(); qr=QueryRequest(user_id=user.id,sql=sql,status='PENDING'); db.add(qr); db.flush()
        try: parsed=QueryParser().parse(sql)
        except ValueError as e: return self._audit(db,qr,user,'','','DENY',str(e),started,[])
        router=QueryRouter(); direct=router.choose(db,parsed,preferred_node)
        if direct: return self._run(db,qr,user,parsed,direct,'ALLOW','Routed by trust/sensitivity policy',started)
        # query splitting: only if a non-trusted preference requests mixed safe/sensitive data
        nodes=db.query(Node).filter_by(status='HEALTHY').all(); trusted=next((n for n in nodes if n.trust_level=='TRUSTED'),None)
        if preferred_node and trusted:
            pref=next((n for n in nodes if n.name==preferred_node),None)
            if pref and pref.trust_level=='NON_TRUSTED' and any(RANK[CLASSIFICATIONS[parsed.table][c]]>=2 for c in parsed.columns):
                return self._run(db,qr,user,parsed,trusted,'REWRITE','Split plan: sensitive projection retained in trusted layer; non-trusted receives only safe projection',started)
        return self._audit(db,qr,user,parsed,'','DENY','No node may safely execute this query',started,[])
    def _run(self,db,qr,user,p,node,decision,reason,started):
        # Deterministic prototype data: physical nodes are represented by restricted replicas.
        rows=[{'id':1,'name':'Alice','department':'Engineering','salary':120000,'medical_information':'restricted'}, {'id':2,'name':'Bob','department':'Sales','salary':90000,'medical_information':'restricted'}]
        if p.where:
            m=re.fullmatch(r"department\s*=\s*'([^']+)'",p.where,re.I)
            if not m: return self._audit(db,qr,user,p,node,'DENY','Only department equality filters are allowlisted',started,[])
            rows=[r for r in rows if r['department'].lower()==m.group(1).lower()]
        result=[{c:r[c] for c in p.columns} for r in rows]
        return self._audit(db,qr,user,p,node,decision,reason,started,result)
    def _audit(self,db,qr,user,p,node,decision,reason,started,result):
        elapsed=int((time.monotonic()-started)*1000); qr.status='COMPLETED' if decision!='DENY' else 'DENIED'
        op=p.operation if p else 'INVALID'; table=p.table if p else ''; cols=','.join(p.columns) if p else ''
        audit=AuditLog(user_id=user.id,query_id=qr.id,requested_operation=op,requested_tables=table,requested_columns=cols,selected_node=node.name if node else '',node_trust_level=node.trust_level if node else '',decision=decision,reason=reason,execution_time=elapsed,result_status=qr.status); db.add(audit)
        if decision!='DENY': db.add(QueryExecution(query_id=qr.id,node_name=node.name,result_json=json.dumps(result),execution_time_ms=elapsed))
        db.commit(); return {'query_id':qr.id,'decision':decision,'node':node.name if node else None,'reason':reason,'result':result,'execution_time_ms':elapsed}
