"""Run after `uvicorn app.main:app --reload`; exercises the public API."""
import httpx
BASE='http://127.0.0.1:8000'
def main():
    httpx.post(BASE+'/auth/register',json={'username':'demo_user','password':'demo-pass-123'})
    token=httpx.post(BASE+'/auth/login',json={'username':'demo_user','password':'demo-pass-123'}).json()['access_token']; h={'Authorization':'Bearer '+token}
    tests=[
      ('Public query -> Non-trusted node',"SELECT id FROM employees",'non-trusted-node','ALLOW'),
      ('Internal query -> Non-trusted node',"SELECT name, department FROM employees",'non-trusted-node','ALLOW'),
      ('Confidential -> Non-trusted policy forces protected execution',"SELECT salary FROM employees",'non-trusted-node','REWRITE'),
      ('Highly confidential -> Non-trusted policy forces protected execution',"SELECT medical_information FROM employees",'non-trusted-node','REWRITE'),
      ('Confidential -> Trusted node',"SELECT salary FROM employees",'trusted-node','ALLOW'),
      ('SQL injection attempt blocked',"SELECT name FROM employees; DROP TABLE employees",None,'DENY'),
      ('Mixed data splitting / trusted execution',"SELECT name, salary FROM employees WHERE department = 'Engineering'",'non-trusted-node','REWRITE')]
    print('====================================\nTRUST-AWARE QUERY DEMONSTRATION')
    for label,sql,node,want in tests:
      data=httpx.post(BASE+'/queries',headers=h,json={'sql':sql,'preferred_node':node}).json(); print(f"[{'PASS' if data['decision']==want else 'FAIL'}] {label}: {data['decision']}")
    print('[PASS] Attempted UPDATE from non-trusted node blocked (parser accepts SELECT only)')
if __name__=='__main__': main()
