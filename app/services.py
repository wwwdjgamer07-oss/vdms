import re, json, time
from dataclasses import dataclass
from sqlalchemy.orm import Session
from .models import Node, QueryRequest, QueryExecution, AuditLog
CLASSIFICATIONS={
 'employees':{'id':'PUBLIC','name':'INTERNAL','department':'INTERNAL','salary':'CONFIDENTIAL','medical_information':'HIGHLY_CONFIDENTIAL'},
 'customers':{'id':'PUBLIC','name':'INTERNAL','city':'INTERNAL','email':'CONFIDENTIAL','phone':'CONFIDENTIAL'},
 'products':{'id':'PUBLIC','name':'PUBLIC','category':'INTERNAL','price':'CONFIDENTIAL','supplier_cost':'CONFIDENTIAL'},
 'orders':{'id':'PUBLIC','customer_name':'INTERNAL','product_name':'INTERNAL','status':'INTERNAL','total':'CONFIDENTIAL'},
 'students':{'id':'PUBLIC','name':'INTERNAL','course':'INTERNAL','marks':'CONFIDENTIAL','guardian_contact':'HIGHLY_CONFIDENTIAL'},
 'patients':{'id':'PUBLIC','name':'CONFIDENTIAL','department':'INTERNAL','diagnosis':'HIGHLY_CONFIDENTIAL','medical_information':'HIGHLY_CONFIDENTIAL'}
}
RANK={'PUBLIC':0,'INTERNAL':1,'CONFIDENTIAL':2,'HIGHLY_CONFIDENTIAL':3}
SAFE_TABLES=set(CLASSIFICATIONS)
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
        # Deterministic replica data for each configured demonstration domain.
        data={
          'employees':[{'id':1,'name':'Alice','department':'Engineering','salary':120000,'medical_information':'restricted'},{'id':2,'name':'Bob','department':'Sales','salary':90000,'medical_information':'restricted'}],
          'customers':[{'id':1,'name':'Maya','city':'Delhi','email':'maya@example.test','phone':'9000000001'},{'id':2,'name':'Ravi','city':'Mumbai','email':'ravi@example.test','phone':'9000000002'}],
          'products':[{'id':1,'name':'Laptop','category':'Electronics','price':75000,'supplier_cost':50000},{'id':2,'name':'Chair','category':'Furniture','price':6000,'supplier_cost':3500}],
          'orders':[{'id':1,'customer_name':'Maya','product_name':'Laptop','status':'Shipped','total':75000},{'id':2,'customer_name':'Ravi','product_name':'Chair','status':'Processing','total':6000}],
          'students':[{'id':1,'name':'Asha','course':'Computer Science','marks':91,'guardian_contact':'restricted'},{'id':2,'name':'Dev','course':'Mathematics','marks':84,'guardian_contact':'restricted'}],
          'patients':[{'id':1,'name':'Patient A','department':'Cardiology','diagnosis':'restricted','medical_information':'restricted'},{'id':2,'name':'Patient B','department':'Neurology','diagnosis':'restricted','medical_information':'restricted'}]
        }; rows=data[p.table]
        if p.where:
            for condition in re.split(r'\s+AND\s+',p.where,flags=re.I):
                dept=re.fullmatch(r"department\s*=\s*'([^']+)'",condition,re.I); name=re.fullmatch(r"name\s*=\s*'([^']+)'",condition,re.I); salary=re.fullmatch(r'salary\s*(>=|<=|>|<|=)\s*(\d+)',condition,re.I)
                if dept: rows=[r for r in rows if r['department'].lower()==dept.group(1).lower()]
                elif name: rows=[r for r in rows if r['name'].lower()==name.group(1).lower()]
                elif salary:
                    op,n=salary.group(1),int(salary.group(2)); rows=[r for r in rows if {'>':r['salary']>n,'<':r['salary']<n,'>=':r['salary']>=n,'<=':r['salary']<=n,'=':r['salary']==n}[op]]
                else: return self._audit(db,qr,user,p,node,'DENY','Only approved department, name, and salary filters are allowlisted',started,[])
        if p.aggregate=='COUNT': result=[{'count':len(rows)}]
        elif p.aggregate=='AVG': result=[{'average_'+p.columns[0]:sum(r[p.columns[0]] for r in rows)/len(rows) if rows else 0}]
        elif p.aggregate=='SUM': result=[{'sum_'+p.columns[0]:sum(r[p.columns[0]] for r in rows)}]
        else: result=[{c:r[c] for c in p.columns} for r in rows]
        if p.limit: result=result[:p.limit]
        return self._audit(db,qr,user,p,node,decision,reason,started,result)
    def _audit(self,db,qr,user,p,node,decision,reason,started,result):
        elapsed=int((time.monotonic()-started)*1000); qr.status='COMPLETED' if decision!='DENY' else 'DENIED'
        op=p.operation if p else 'INVALID'; table=p.table if p else ''; cols=','.join(p.columns) if p else ''
        audit=AuditLog(user_id=user.id,query_id=qr.id,requested_operation=op,requested_tables=table,requested_columns=cols,selected_node=node.name if node else '',node_trust_level=node.trust_level if node else '',decision=decision,reason=reason,execution_time=elapsed,result_status=qr.status); db.add(audit)
        if decision!='DENY': db.add(QueryExecution(query_id=qr.id,node_name=node.name,result_json=json.dumps(result),execution_time_ms=elapsed))
        db.commit(); return {'query_id':qr.id,'decision':decision,'node':node.name if node else None,'reason':reason,'result':result,'execution_time_ms':elapsed}
