/**
 * @name CVE-2009-2693 in tomcat
 * @kind path-problem
 * @problem.severity error
 * @precision high
 *  *@tags security
 *      external/cwe/cwe-022
 */
import java
import semmle.code.java.dataflow.FlowSources
import DataFlow
import PathGraph
import semmle.code.java.controlflow.Guards
import semmle.code.java.dataflow.SSA
// import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking2


// from Variable v
// where v.hasName("contextPath")
// select v, v.getLocation()


// from Method method, Call call
// where method = call.getCallee() and method.hasName("getPath") and
// method.getDeclaringType().hasQualifiedName("org.apache.catalina", "Context")
// select call, call.getLocation()

class TaintSourceMethod extends Method {
    TaintSourceMethod() {
        this.getDeclaringType().getASupertype*().hasQualifiedName("org.apache.catalina", "Context")
        and
        this.hasName("getPath")
    }
  }
// from TomcatPathTraverseMethod m, Call c
// where c.getCallee() = m
// select c, c.getLocation()
class TaintSinkMethod extends Expr {
    TaintSinkMethod() {
        exists(ConstructorCall ctr,int n | this = ctr.getArgument(n) |
        exists(Class c | ctr.getConstructor() = c.getAConstructor() |
            c.hasQualifiedName("java.io", "FileOutputStream") or
            c.hasQualifiedName("java.io", "RandomAccessFile") or
            c.hasQualifiedName("java.io", "FileWriter") or
            c.hasQualifiedName("java.io", "File")
        )
        )
        or
        exists(MethodAccess call, int n | this = call.getArgument(n) |
        call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
        (
            call.getMethod().getName().regexpMatch("new.*Reader|newOutputStream|create.*") and n = 0
            or
            call.getMethod().hasName("copy") and n = 1
            or
            call.getMethod().hasName("move") and n = 1
        )
        )
    }
}

// predicate filePathStep(ExprNode n1, ExprNode n2) {
//     exists(ConstructorCall cc | cc.getConstructedType() instanceof TypeFile |
//       n1.asExpr() = cc.getAnArgument() and
//       n2.asExpr() = cc
//     )
//     or
//     exists(MethodAccess ma, Method m |
//       ma.getMethod() = m and
//       n1.asExpr() = ma.getQualifier() and
//       n2.asExpr() = ma
//     |
//       m.getDeclaringType() instanceof TypeFile and m.hasName("toPath")
//       or
//       m.getDeclaringType() instanceof TypePath and m.hasName("toAbsolutePath")
//       or
//       m.getDeclaringType() instanceof TypePath and m.hasName("toFile")
//     )
//   }

// predicate fileTaintStep(ExprNode n1, ExprNode n2) {
//     exists(MethodAccess ma, Method m |
//       n1.asExpr() = ma.getQualifier() or
//       n1.asExpr() = ma.getAnArgument()
//     |
//       n2.asExpr() = ma and
//       ma.getMethod() = m and
//       m.getDeclaringType() instanceof TypePath and
//       m.hasName("resolve")
//     )
//   }
  
//   predicate localFileValueStep(Node n1, Node n2) {
//     localFlowStep(n1, n2) or
//     filePathStep(n1, n2)
//   }

// predicate localFileValueStepPlus(Node n1, Node n2) = fastTC(localFileValueStep/2)(n1, n2)

// predicate validateFilePath(SsaVariable var, Guard check) {
//     // `var.getCanonicalFile().toPath().startsWith(...)`,
//     // `var.getCanonicalPath().startsWith(...)`, or
//     // `var.toPath().normalize().startsWith(...)`
//     exists(MethodAccess normalize, MethodAccess startsWith, Node n1, Node n2, Node n3, Node n4 |
//       n1.asExpr() = var.getAUse() and
//       n2.asExpr() = normalize.getQualifier() and
//       (n1 = n2 or localFileValueStepPlus(n1, n2)) and
//       n3.asExpr() = normalize and
//       n4.asExpr() = startsWith.getQualifier() and
//       (n3 = n4 or localFileValueStepPlus(n3, n4)) and
//       check = startsWith and
//       startsWith.getMethod().hasName("startsWith") and
//       (
//         normalize.getMethod().hasName("getCanonicalFile") or
//         normalize.getMethod().hasName("getCanonicalPath") or
//         normalize.getMethod().hasName("normalize")
//       )
//     )
//   }
  
//   /**
//    * Holds if `m` validates its `arg`th parameter.
//    */
//   predicate validationMethod(Method m, int arg) {
//     exists(Guard check, SsaImplicitInit var, ControlFlowNode exit, ControlFlowNode normexit |
//       validateFilePath(var, check) and
//       var.isParameterDefinition(m.getParameter(arg)) and
//       exit = m and
//       normexit.getANormalSuccessor() = exit and
//       1 = strictcount(ControwanlFlowNode n | n.getANormalSuccessor() = exit)
//     |
//       check.(ConditionNode).getATrueSuccessor() = exit or
//       check.controls(normexit.getBasicBlock(), true)
//     )
//   }
  

class TaintConfig extends TaintTracking::Configuration{
    TaintConfig(){
        this = "CWE-22"
    }

    override predicate isSource(DataFlow::Node source){
        source.asExpr().(MethodAccess).getMethod() instanceof TaintSourceMethod
    }

    override predicate isSink(DataFlow::Node sink){
        sink.asExpr() instanceof TaintSinkMethod
    }

}

// from TomcatPathTraverseMethod m, Call call
// where call.getCallee() = m
// select call, call.getLocation()

// from WrittenFileName w
// select w, w.getLocation()

// from Constructor con, Call call
// where con.getDeclaringType().hasQualifiedName("java.io", "File")
// and call.getCallee() = con
// select call, call.getLocation(), call.getArgument(0)

from PathNode source, PathNode sink, TomcatTaintConfig config
where config.hasFlowPath(source, sink) 
select source.getNode(),source,sink,
  "Path Traverse problem, which path may contain '..', is used in a $@.", sink.getNode(),
  "file system operation"

// from PartialPathNode source, PartialPathNode sink, TomcatTaintConfig config
// where config.hasPartialFlow(source, sink, 0)
// select source.getNode(),source,sink,
//   "Path Traverse problem, which path may contain '..', is used in a $@.", sink.getNode(),
//   "file system operation"
