# -*- coding:utf-8 -*-
import networkx as nx


from py2neo import Graph, Node, Relationship
url = "http://localhost:7474"
username = "neo4j"
password = "snail"


# 连接数据库
def connect_neo4j():
    graph = Graph(url, username=username, password=password)
    return graph
