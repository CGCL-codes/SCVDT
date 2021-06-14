import sys

from py2neo import Graph

print("this is a test")
url = "http://localhost:7474"
username = "neo4j"
password = "snail"


# 连接数据库
def connect_neo4j():
    graph = Graph(url, username=username, password=password)
    print("111")
    return graph


db = connect_neo4j()