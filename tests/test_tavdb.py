import os
os.environ['DATABASE_URL']='sqlite:///./test_tavdb.db'
from fastapi.testclient import TestClient
from app.main import app
from app.services import AdaptiveRoutingLearner
def client():
    c=TestClient(app); c.__enter__(); return c
def auth(c, name='tester'):
    c.post('/auth/register',json={'username':name,'password':'password1'})
    return {'Authorization':'Bearer '+c.post('/auth/login',json={'username':name,'password':'password1'}).json()['access_token']}
def run(c,h,sql,node=None): return c.post('/queries',headers=h,json={'sql':sql,'preferred_node':node}).json()
def test_register_login():
 c=client(); h=auth(c,'alpha'); assert h['Authorization'].startswith('Bearer '); c.__exit__(None,None,None)
def test_auth_required():
 c=client(); assert c.get('/nodes').status_code==403; c.__exit__(None,None,None)
def test_nodes_seeded():
 c=client(); h=auth(c,'beta'); assert len(c.get('/nodes',headers=h).json())>=3; c.__exit__(None,None,None)
def test_public_nontrusted():
 c=client();h=auth(c,'c1');assert run(c,h,'SELECT id FROM employees','non-trusted-node')['decision']=='ALLOW';c.__exit__(None,None,None)
def test_internal_nontrusted():
 c=client();h=auth(c,'c2');assert run(c,h,'SELECT name FROM employees','non-trusted-node')['decision']=='ALLOW';c.__exit__(None,None,None)
def test_confidential_rewritten():
 c=client();h=auth(c,'c3');assert run(c,h,'SELECT salary FROM employees','non-trusted-node')['decision']=='REWRITE';c.__exit__(None,None,None)
def test_highly_confidential_rewritten():
 c=client();h=auth(c,'c4');assert run(c,h,'SELECT medical_information FROM employees','non-trusted-node')['decision']=='REWRITE';c.__exit__(None,None,None)
def test_confidential_trusted():
 c=client();h=auth(c,'c5');assert run(c,h,'SELECT salary FROM employees','trusted-node')['decision']=='ALLOW';c.__exit__(None,None,None)
def test_injection_blocked():
 c=client();h=auth(c,'c6');assert run(c,h,'SELECT id FROM employees; DROP TABLE employees')['decision']=='DENY';c.__exit__(None,None,None)
def test_drop_blocked():
 c=client();h=auth(c,'c7');assert run(c,h,'DROP TABLE employees')['decision']=='DENY';c.__exit__(None,None,None)
def test_update_blocked():
 c=client();h=auth(c,'c8');assert run(c,h,"UPDATE employees SET salary=1")['decision']=='DENY';c.__exit__(None,None,None)
def test_unknown_column():
 c=client();h=auth(c,'c9');assert run(c,h,'SELECT secret FROM employees')['decision']=='DENY';c.__exit__(None,None,None)
def test_where_filter():
 c=client();h=auth(c,'c10');assert len(run(c,h,"SELECT name FROM employees WHERE department = 'Engineering'",'non-trusted-node')['result'])==1;c.__exit__(None,None,None)
def test_audit_exists():
 c=client();h=auth(c,'c11');run(c,h,'SELECT id FROM employees');assert c.get('/audit/logs',headers=h).json();c.__exit__(None,None,None)
def test_database_crud():
 c=client();h=auth(c,'c12');name='demo-c12';c.post('/databases',headers=h,json={'name':name,'description':'x'});assert any(x['name']==name for x in c.get('/databases',headers=h).json());c.__exit__(None,None,None)
def test_query_lookup():
 c=client();h=auth(c,'c13');q=run(c,h,'SELECT id FROM employees');assert c.get('/queries/'+str(q['query_id']),headers=h).status_code==200;c.__exit__(None,None,None)
def test_natural_language_query():
 c=client();h=auth(c,'c14');r=c.post('/queries/natural',headers=h,json={'prompt':'show employee names in Engineering','preferred_node':'non-trusted-node'}).json();assert r['decision']=='ALLOW' and r['interpreted_sql'].startswith('SELECT name');c.__exit__(None,None,None)
def test_natural_language_sensitive_rewrite():
 c=client();h=auth(c,'c15');r=c.post('/queries/natural',headers=h,json={'prompt':'show salaries','preferred_node':'non-trusted-node'}).json();assert r['decision']=='REWRITE';c.__exit__(None,None,None)
def test_natural_language_salary_filter_and_limit():
 c=client();h=auth(c,'c16');r=c.post('/queries/natural',headers=h,json={'prompt':'list the top 1 employee names with salary above 100,000'}).json();assert r['result'][0]['name']=='Alice';c.__exit__(None,None,None)
def test_natural_language_average():
 c=client();h=auth(c,'c17');r=c.post('/queries/natural',headers=h,json={'prompt':'what is the average salary'}).json();assert r['result'][0]['average_salary']==105000;c.__exit__(None,None,None)
def test_general_purpose_customer_request():
 c=client();h=auth(c,'c18');r=c.post('/queries/natural',headers=h,json={'prompt':'show customer names'}).json();assert r['result'][0]['name']=='Maya' and 'FROM customers' in r['interpreted_sql'];c.__exit__(None,None,None)
def test_general_purpose_product_request():
 c=client();h=auth(c,'c19');r=c.post('/queries/natural',headers=h,json={'prompt':'list product names and prices'}).json();assert r['decision']=='ALLOW' and r['result'][0]['name']=='Laptop';c.__exit__(None,None,None)
def test_adaptive_learner_records_history():
 c=client();h=auth(c,'c20');run(c,h,'SELECT id FROM employees','non-trusted-node');from app.database import SessionLocal;from app.models import Node;db=SessionLocal();score,stats=AdaptiveRoutingLearner().score(db,db.query(Node).filter_by(name='non-trusted-node').first());db.close();assert stats['samples']>=1 and score>=0;c.__exit__(None,None,None)
def test_persistent_data_crud_and_query():
 c=client();h=auth(c,'c21');created=c.post('/data/employees',headers=h,json={'values':{'name':'Cara','department':'Engineering','salary':110000,'medical_information':'restricted'}});assert created.status_code==201;record=created.json();assert record['name']=='Cara' and record['storage_node']=='non-trusted-node';assert c.get('/data/employees/'+str(record['id'])+'/replicas',headers=h).json()[0]['integrity_hash'];assert c.put('/data/employees/'+str(record['id']),headers=h,json={'values':{'department':'Security'}}).json()['department']=='Security';rows=run(c,h,"SELECT name FROM employees WHERE department = 'Security'",'non-trusted-node')['result'];assert any(row['name']=='Cara' for row in rows);assert c.delete('/data/employees/'+str(record['id']),headers=h).status_code==204;c.__exit__(None,None,None)
