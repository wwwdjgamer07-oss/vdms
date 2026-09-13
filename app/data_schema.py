"""Persistent application tables for the trust-aware query layer."""
from sqlalchemy import Column, Float, Integer, MetaData, String, Table, func, select

CLASSIFICATIONS = {
    'employees': {'id':'PUBLIC','name':'INTERNAL','department':'INTERNAL','salary':'CONFIDENTIAL','medical_information':'HIGHLY_CONFIDENTIAL'},
    'customers': {'id':'PUBLIC','name':'INTERNAL','city':'INTERNAL','email':'CONFIDENTIAL','phone':'CONFIDENTIAL'},
    'products': {'id':'PUBLIC','name':'PUBLIC','category':'INTERNAL','price':'CONFIDENTIAL','supplier_cost':'CONFIDENTIAL'},
    'orders': {'id':'PUBLIC','customer_name':'INTERNAL','product_name':'INTERNAL','status':'INTERNAL','total':'CONFIDENTIAL'},
    'students': {'id':'PUBLIC','name':'INTERNAL','course':'INTERNAL','marks':'CONFIDENTIAL','guardian_contact':'HIGHLY_CONFIDENTIAL'},
    'patients': {'id':'PUBLIC','name':'CONFIDENTIAL','department':'INTERNAL','diagnosis':'HIGHLY_CONFIDENTIAL','medical_information':'HIGHLY_CONFIDENTIAL'},
}
NUMERIC_COLUMNS = {'salary', 'price', 'supplier_cost', 'total', 'marks'}
metadata = MetaData()
TABLES = {}
for table_name, columns in CLASSIFICATIONS.items():
    definitions = [Column('id', Integer, primary_key=True, autoincrement=True)]
    for column_name in columns:
        if column_name != 'id':
            definitions.append(Column(column_name, Float if column_name in NUMERIC_COLUMNS else String(255)))
    TABLES[table_name] = Table(table_name, metadata, *definitions)

SAMPLE_ROWS = {
    'employees': [{'name':'Alice','department':'Engineering','salary':120000,'medical_information':'restricted'}, {'name':'Bob','department':'Sales','salary':90000,'medical_information':'restricted'}],
    'customers': [{'name':'Maya','city':'Delhi','email':'maya@example.test','phone':'9000000001'}, {'name':'Ravi','city':'Mumbai','email':'ravi@example.test','phone':'9000000002'}],
    'products': [{'name':'Laptop','category':'Electronics','price':75000,'supplier_cost':50000}, {'name':'Chair','category':'Furniture','price':6000,'supplier_cost':3500}],
    'orders': [{'customer_name':'Maya','product_name':'Laptop','status':'Shipped','total':75000}, {'customer_name':'Ravi','product_name':'Chair','status':'Processing','total':6000}],
    'students': [{'name':'Asha','course':'Computer Science','marks':91,'guardian_contact':'restricted'}, {'name':'Dev','course':'Mathematics','marks':84,'guardian_contact':'restricted'}],
    'patients': [{'name':'Patient A','department':'Cardiology','diagnosis':'restricted','medical_information':'restricted'}, {'name':'Patient B','department':'Neurology','diagnosis':'restricted','medical_information':'restricted'}],
}

def create_data_tables(engine):
    metadata.create_all(engine)

def seed_data(db):
    for name, table in TABLES.items():
        if not db.execute(select(func.count()).select_from(table)).scalar_one():
            db.execute(table.insert(), SAMPLE_ROWS[name])
    db.commit()
