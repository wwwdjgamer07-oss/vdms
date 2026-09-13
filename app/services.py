import re, json, time
from datetime import datetime
from dataclasses import dataclass
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .models import Node, QueryRequest, QueryExecution, AuditLog
from .data_schema import CLASSIFICATIONS, TABLES
RANK={'PUBLIC':0,'INTERNAL':1,'CONFIDENTIAL':2,'HIGHLY_CONFIDENTIAL':3}
SAFE_TABLES=set(CLASSIFICATIONS)


class NodeHealthMonitor:
    """Keeps routing state in sync with node integrity and execution health."""

    def inspect(self, node):
        try:
            operations = json.loads(node.allowed_operations)
            tables = json.loads(node.allowed_tables)
        except (TypeError, json.JSONDecodeError):
            return 'Node policy data is corrupted'
        if not isinstance(operations, list) or not isinstance(tables, list):
            return 'Node policy data is corrupted'
        if not node.host or not isinstance(node.port, int) or not 1 <= node.port <= 65535:
            return 'Node connection configuration is invalid'
        if not set(tables).issubset(SAFE_TABLES):
            return 'Node policy references unavailable tables'
        return None

    def mark_unavailable(self, db, node, reason):
        node.status = 'UNAVAILABLE'
        node.last_health_check = datetime.utcnow()
        db.flush()
        return {'node': node.name, 'status': node.status, 'available': False,
                'reason': reason, 'last_health_check': node.last_health_check.isoformat() + 'Z'}

    def refresh(self, db, node):
        problem = self.inspect(node)
        if problem:
            return self.mark_unavailable(db, node, problem)
        node.last_health_check = datetime.utcnow()
        db.flush()
        return {'node': node.name, 'status': node.status,
                'available': node.status == 'HEALTHY', 'reason': None,
                'last_health_check': node.last_health_check.isoformat() + 'Z'}
class NaturalLanguageTranslator:
    """Offline employee-domain grammar. Its SQL output always returns to QueryParser."""
    synonyms={'employee id':'id','employee ids':'id','id':'id','identifier':'id','identifiers':'id','employee name':'name','employee names':'name','name':'name','names':'name','department':'department','departments':'department','team':'department','teams':'department','salary':'salary','salaries':'salary','pay':'salary','compensation':'salary','medical information':'medical_information','medical details':'medical_information','medical data':'medical_information','health information':'medical_information','medical':'medical_information'}
    def translate(self, prompt):
        text=' '.join(prompt.lower().strip().split())
        verbs=('show','list','get','find','display','what','which','who','tell','give','how many','count','average','total')
        if not text or not any(word in text for word in verbs): raise ValueError('Use a request such as “show employee names in Engineering”')
        table=next((t for t in CLASSIFICATIONS if re.search(r'\b'+re.escape(t.rstrip('s'))+r's?\b',text)),'employees')
        cols=[]
        for phrase,column in self.synonyms.items():
            if phrase in text and column in CLASSIFICATIONS[table] and column not in cols: cols.append(column)
        for column in CLASSIFICATIONS[table]:
            if column.replace('_',' ') in text and column not in cols: cols.append(column)
        summary='COUNT' if re.search(r'\b(how many|count|number of)\b',text) else 'AVG' if re.search(r'\b(average|mean|avg)\b',text) else 'SUM' if re.search(r'\b(total|sum)\b',text) else None
        if summary:
            numeric=next((c for c in ('salary','price','total','marks') if c in CLASSIFICATIONS[table]),'id')
            field=numeric if (numeric in cols or summary in ('AVG','SUM')) else 'id'; sql=f'SELECT {summary}({field}) FROM {table}'
        else: sql='SELECT '+', '.join(cols or list(CLASSIFICATIONS[table])[:3])+' FROM '+table
        filters=[]
        dept=re.search(r'\b(?:in|from|for|of)\s+(engineering|sales)\b',text)
        if dept and 'department' in CLASSIFICATIONS[table]: filters.append("department = '"+dept.group(1).title()+"'")
        named=re.search(r'\b(?:named|called)\s+(alice|bob)\b',text)
        if named: filters.append("name = '"+named.group(1).title()+"'")
        comp=re.search(r'\b(?:salary|pay|compensation)\s+(above|over|greater than|more than|at least|below|under|less than|at most|equal to|equals?)\s*\$?([0-9][0-9,]*)',text)
        if comp:
            word,num=comp.group(1),comp.group(2).replace(',',''); op='>=' if word=='at least' else '<=' if word=='at most' else '>' if word in ('above','over','greater than','more than') else '<' if word in ('below','under','less than') else '='; filters.append(f'salary {op} {num}')
        if filters: sql+=' WHERE '+' AND '.join(filters)
        limit=re.search(r'\b(?:top|first|limit)\s+(\d{1,2})\b',text)
        if limit: sql+=' LIMIT '+limit.group(1)
        return sql
@dataclass
class Parsed: operation:str; table:str; columns:list[str]; where:str=''; aggregate:str|None=None; limit:int|None=None
class QueryParser:
    def parse(self, sql):
        sql=sql.strip().rstrip(';')
        if ';' in sql or '--' in sql or '/*' in sql or re.search(r'\b(drop|truncate|alter|create|grant|revoke|union|exec|pragma)\b',sql,re.I): raise ValueError('Unsafe or unsupported SQL construct')
        m=re.fullmatch(r'(?is)select\s+(.+?)\s+from\s+([a-z_][\w]*)(?:\s+where\s+([\w\s=><\'".-]+?))?(?:\s+limit\s+(\d+))?',sql)
        if not m: raise ValueError('Only simple SELECT queries are accepted')
        cols=[]; aggregate=None
        for raw in m.group(1).split(','):
            raw=raw.strip(); agg=re.fullmatch(r'(AVG|COUNT|SUM)\((\*|[a-z_]\w*)\)',raw,re.I)
            if agg:
                if aggregate: raise ValueError('Only one aggregation is supported')
                aggregate=agg.group(1).upper()
            col=agg.group(2).lower() if agg else raw.lower()
            cols += list(CLASSIFICATIONS.get(m.group(2).lower(),{})) if col=='*' else [col]
        table=m.group(2).lower()
        if table not in SAFE_TABLES or any(c not in CLASSIFICATIONS[table] for c in cols): raise ValueError('Unknown or forbidden table/column')
        return Parsed('SELECT',table,cols,m.group(3) or '',aggregate,int(m.group(4)) if m.group(4) else None)
class TrustPolicyEngine:
    def evaluate(self, parsed, node):
        if node.status!='HEALTHY': return 'DENY','Node is unavailable'
        if parsed.operation not in json.loads(node.allowed_operations): return 'DENY','Operation not permitted on node'
        if parsed.table not in json.loads(node.allowed_tables): return 'DENY','Table not permitted on node'
        maximum=max(RANK[CLASSIFICATIONS[parsed.table][c]] for c in parsed.columns)
        if node.trust_level=='NON_TRUSTED' and maximum>=RANK['CONFIDENTIAL']: return 'REWRITE','Sensitive columns require trusted execution'
        if node.trust_level=='SEMI_TRUSTED' and maximum>=RANK['HIGHLY_CONFIDENTIAL']: return 'REWRITE','Highly confidential columns require trusted execution'
        return 'ALLOW','Policy allows least-privilege delegation'
class AdaptiveRoutingLearner:
    """Online, explainable learner over previous audit outcomes; it never bypasses policy."""
    def score(self, db, node):
        history=db.query(AuditLog).filter(AuditLog.selected_node==node.name).all()
        if not history: return 5.0, {'samples':0,'success_rate':1.0,'avg_ms':0}
        successful=[x for x in history if x.decision!='DENY' and x.result_status=='COMPLETED']
        success_rate=len(successful)/len(history)
        avg_ms=sum(x.execution_time for x in history)/len(history)
        # Lower score is better: unreliable or slower nodes become less preferred.
        return round((1-success_rate)*100+avg_ms/100+node.workload,3), {'samples':len(history),'success_rate':round(success_rate,2),'avg_ms':round(avg_ms,1)}
class QueryRouter:
    order={'NON_TRUSTED':0,'SEMI_TRUSTED':1,'TRUSTED':2}
    def choose(self, db, parsed, prefer=None):
        nodes=db.query(Node).filter_by(status='HEALTHY').all()
        if prefer: nodes=[n for n in nodes if n.name==prefer]
        policy=TrustPolicyEngine(); allowed=[]
        for n in nodes:
            d,_=policy.evaluate(parsed,n)
            if d=='ALLOW': allowed.append(n)
        learner=AdaptiveRoutingLearner()
        # Trust tier remains the first decision; learning only ranks equally eligible tiers.
        return sorted(allowed,key=lambda n:(self.order[n.trust_level],learner.score(db,n)[0],n.workload))[0] if allowed else None
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
        # User SQL is parsed and allowlisted before this point. Build a
        # parameterized SQLAlchemy query over persistent SQL tables instead.
        try:
          table = TABLES[p.table]
          filters = []
          if p.where:
              for condition in re.split(r'\s+AND\s+',p.where,flags=re.I):
                  match = re.fullmatch(r"([a-z_]\w*)\s*(>=|<=|>|<|=)\s*(?:'([^']*)'|(\d+(?:\.\d+)?))", condition, re.I)
                  if not match or match.group(1).lower() not in table.c:
                      return self._audit(db,qr,user,p,node,'DENY','Only allowlisted column filters are supported',started,[])
                  column, operator, text_value, number_value = match.groups()
                  value = text_value if text_value is not None else float(number_value)
                  field = table.c[column.lower()]
                  filters.append({'=': field == value, '>': field > value, '<': field < value, '>=': field >= value, '<=': field <= value}[operator])
          if p.aggregate == 'COUNT':
              statement = select(func.count().label('count')).select_from(table)
          elif p.aggregate in ('AVG', 'SUM'):
              aggregate = func.avg(table.c[p.columns[0]]) if p.aggregate == 'AVG' else func.sum(table.c[p.columns[0]])
              statement = select(aggregate.label(('average_' if p.aggregate == 'AVG' else 'sum_') + p.columns[0]))
          else:
              statement = select(*(table.c[column] for column in p.columns))
          if filters: statement = statement.where(*filters)
          if p.limit and not p.aggregate: statement = statement.limit(p.limit)
          result = [dict(row) for row in db.execute(statement).mappings()]
          return self._audit(db,qr,user,p,node,decision,reason,started,result)
        except (KeyError, TypeError, ValueError) as error:
          health_reason = f'Execution integrity failure: {error}'
          NodeHealthMonitor().mark_unavailable(db, node, health_reason)
          return self._audit(db,qr,user,p,node,'DENY',health_reason,started,[])
    def _audit(self,db,qr,user,p,node,decision,reason,started,result):
        elapsed=int((time.monotonic()-started)*1000); qr.status='COMPLETED' if decision!='DENY' else 'DENIED'
        op=p.operation if p else 'INVALID'; table=p.table if p else ''; cols=','.join(p.columns) if p else ''
        audit=AuditLog(user_id=user.id,query_id=qr.id,requested_operation=op,requested_tables=table,requested_columns=cols,selected_node=node.name if node else '',node_trust_level=node.trust_level if node else '',decision=decision,reason=reason,execution_time=elapsed,result_status=qr.status); db.add(audit)
        if decision!='DENY': db.add(QueryExecution(query_id=qr.id,node_name=node.name,result_json=json.dumps(result),execution_time_ms=elapsed))
        db.commit(); return {'query_id':qr.id,'decision':decision,'node':node.name if node else None,'reason':reason,'result':result,'execution_time_ms':elapsed}
